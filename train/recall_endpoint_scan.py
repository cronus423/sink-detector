#!/usr/bin/env python3
"""Recall-oriented attack-endpoint scanner.

Goal: find every function that *performs a final security effect* (an attack
endpoint, per the project's sink definition: setuid/exec/file-mutation/...),
independent of any model score, and diff it against codex's curated true_sink
set. This recovers endpoints the XGBoost-filtered review pipeline never looked
at (predicted_negative -> never reviewed -> silently dropped).

Method:
  1. Brace-depth C parser attributes every effect-primitive call site to its
     enclosing top-level function (comments/strings stripped first).
  2. Keep only functions that resolve in the binary's DWARF function table
     (so they are real, compiled, and feature-extractable for training).
  3. Cross-reference codex's per-program review verdict.

Output: JSON + markdown listing, and a merged positive-label JSONL fragment
that can feed XGBoost retraining.
"""
from __future__ import annotations
import csv, json, re, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]          # program_targets/
SCANS = ROOT / "ml_dataset" / "program_scans"

# program -> (source root, dwarf_facts.json)
PROGRAMS = {
    "openssh_9_7p1":          "source/openssh-9.7p1",
    "sudo_1_8_31":            "source/sudo-1.8.31",
    "proftpd_1_3_3c":         "source/proftpd-dfsg-1.3.3a",
    "vsftpd_3_0_5":           "source/vsftpd-3.0.5",
    "wu_ftpd_2_6_1":          "source/wu-ftpd-2.6.1",
    "polkit_0_105_31":        "source/polkit-0.105",
    "cherry_http_4b877df":    "source/cherry",
    "microhttpserver_4398570":"source/MicroHttpServer",
    "thttpd_2_29":            "source/thttpd-2.29",
    "lighttpd_1_4_59":        "source",
}

# Final-effect primitives = attack ENDPOINTS (not attack surface/origins).
# Path canonicalizers, stat/readlink, generic read/output are intentionally OUT.
EFFECT_PRIMS = {
    # privilege / identity transition
    "setuid":"privilege_identity","seteuid":"privilege_identity","setreuid":"privilege_identity",
    "setresuid":"privilege_identity","setgid":"privilege_identity","setegid":"privilege_identity",
    "setregid":"privilege_identity","setresgid":"privilege_identity","setgroups":"privilege_identity",
    "initgroups":"privilege_identity","setfsuid":"privilege_identity","setfsgid":"privilege_identity",
    # capability / namespace / mount
    "capset":"capability","cap_set_proc":"capability","cap_set_flag":"capability","prctl":"capability",
    "chroot":"capability","pivot_root":"capability","unshare":"capability","setns":"capability",
    "mount":"mount","umount":"mount","umount2":"mount",
    # process execution / code loading
    "execve":"exec","execv":"exec","execvp":"exec","execvpe":"exec","execl":"exec","execlp":"exec",
    "execle":"exec","fexecve":"exec","system":"exec","popen":"exec","posix_spawn":"exec",
    "posix_spawnp":"exec","dlopen":"exec",
    # file mutation (permission / ownership / namespace links / create / delete)
    "chmod":"file_mutation","fchmod":"file_mutation","fchmodat":"file_mutation",
    "chown":"file_mutation","fchown":"file_mutation","lchown":"file_mutation","fchownat":"file_mutation",
    "unlink":"file_mutation","unlinkat":"file_mutation","rename":"file_mutation","renameat":"file_mutation",
    "link":"file_mutation","linkat":"file_mutation","symlink":"file_mutation","symlinkat":"file_mutation",
    "mkdir":"file_mutation","mkdirat":"file_mutation","rmdir":"file_mutation","mknod":"file_mutation",
    "truncate":"file_mutation","ftruncate":"file_mutation","creat":"file_mutation",
    # resource limits / scheduling that gate privilege
    "setrlimit":"rlimit","setpriority":"rlimit",
}
PRIM_RE = re.compile(r'\b(' + '|'.join(map(re.escape, EFFECT_PRIMS)) + r')\s*\(')

SKIP_DIR = {".git","build","target","artifacts","__pycache__","autom4te.cache",
            "regress","tests","test","compat"}  # keep openbsd-compat? skip pure compat shims


def strip_comments_strings(text: str) -> str:
    """Replace comment/string/char contents with spaces, preserving newlines."""
    out=[]; i=0; n=len(text); state=None
    while i<n:
        c=text[i]; nxt=text[i+1] if i+1<n else ''
        if state is None:
            if c=='/' and nxt=='*': state='block'; out.append('  '); i+=2; continue
            if c=='/' and nxt=='/': state='line'; out.append('  '); i+=2; continue
            if c=='"': state='str'; out.append('"'); i+=1; continue
            if c=="'": state='char'; out.append("'"); i+=1; continue
            out.append(c); i+=1; continue
        # inside something
        if state=='block':
            if c=='*' and nxt=='/': state=None; out.append('  '); i+=2; continue
            out.append('\n' if c=='\n' else ' '); i+=1; continue
        if state=='line':
            if c=='\n': state=None; out.append('\n'); i+=1; continue
            out.append(' '); i+=1; continue
        if state in ('str','char'):
            q='"' if state=='str' else "'"
            if c=='\\': out.append('  '); i+=2; continue
            if c==q: state=None; out.append(q); i+=1; continue
            out.append('\n' if c=='\n' else ' '); i+=1; continue
    return ''.join(out)


def parse_functions(path: Path):
    """Yield (func_name, start_line, end_line) for top-level definitions."""
    raw=path.read_text(errors='ignore')
    clean=strip_comments_strings(raw)
    depth=0; header=[]; func=None; start=None
    line=1; funcs=[]
    i=0; n=len(clean)
    # track line numbers as we walk chars
    for ch in clean:
        if ch=='\n': line+=1
        if depth==0:
            if ch in ';}{':
                if ch=='{':
                    # entering a block at top level: parse header for a func name
                    htext=''.join(header)
                    m=re.search(r'([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$', htext.strip())
                    if m:
                        func=m.group(1); start=line
                    else:
                        func=None
                    depth=1
                header=[]
            else:
                header.append(ch)
        else:
            if ch=='{': depth+=1
            elif ch=='}':
                depth-=1
                if depth==0 and func:
                    funcs.append((func,start,line)); func=None
    # return COMMENT/STRING-STRIPPED lines so callers detect real calls only
    # (a `chroot()` / `prctl()` mention inside a comment must not count).
    return funcs, clean.split('\n')


def dwarf_names(prog: str) -> set[str]:
    f=ROOT/prog/"artifacts"/"stage_02_static_ir_cfg"/"dwarf_facts.json"
    if not f.exists(): return set()
    d=json.loads(f.read_text())
    names=set()
    for v in d.get("functions",{}).values():
        if isinstance(v,dict) and v.get("name"): names.add(v["name"])
    return names


CURATED_JSONL = ROOT/"ml_dataset"/"curated_binary_sink_candidates.jsonl"
_CURATED=None
def curated_positives() -> dict[str,set]:
    """target_id -> set(function names) labeled worth_attack=1 in curated seeds."""
    global _CURATED
    if _CURATED is not None: return _CURATED
    out=defaultdict(set)
    if CURATED_JSONL.exists():
        with CURATED_JSONL.open() as f:
            for line in f:
                d=json.loads(line)
                if d.get("label",{}).get("worth_attack")!=1: continue
                tid=d.get("target_id"); br=d.get("binary_resolution",{})
                if br.get("primary_binary_function"):
                    out[tid].add(br["primary_binary_function"])
                for m in br.get("stage03_matches",[]):
                    if m.get("function"): out[tid].add(m["function"])
    _CURATED=out
    return out


def codex_verdicts(prog: str) -> dict[str,str]:
    verd={}
    for fn in ("unlabeled_source_review.csv","likely_sink_add_source_review.csv"):
        p=SCANS/prog/fn
        if p.exists():
            with p.open() as fh:
                rd=csv.DictReader(fh)
                col=rd.fieldnames[0]
                vcol="source_verdict" if "source_verdict" in rd.fieldnames else rd.fieldnames[1]
                verd={r[col]:r[vcol] for r in rd}
            break
    # curated positives override to a known-positive verdict
    for fn in curated_positives().get(prog,()):
        verd[fn]="curated_positive"
    return verd


CALL_RE=re.compile(r'\b([A-Za-z_]\w*)\s*\(')

def scan_program(prog: str, srcsub: str):
    srcroot=ROOT/prog/srcsub
    func_effects=defaultdict(lambda: defaultdict(set))   # func -> cat -> {prims}
    func_callees=defaultdict(set)                        # func -> {callee names}
    func_span={}                                         # func -> body line span
    for cfile in srcroot.rglob("*.c"):
        if any(part in SKIP_DIR for part in cfile.parts): continue
        try: funcs,lines=parse_functions(cfile)
        except Exception: continue
        for fname,s,e in funcs:
            body="\n".join(lines[s-1:e])
            func_callees[fname]={m.group(1) for m in CALL_RE.finditer(body)}
            func_span[fname]=min(func_span.get(fname,10**9), e-s)
            for m in PRIM_RE.finditer(body):
                p=m.group(1); func_effects[fname][EFFECT_PRIMS[p]].add(p)
    # one-hop wrapper propagation: a thin-stub wrapper (name shape) that itself
    # directly calls a primitive is a proxy for that syscall. A function calling
    # such a wrapper reaches the effect (e.g. pr_auth_chroot -> pr_fsio_chroot ->
    # chroot; vsf_privop_do_file_chown -> vsf_sysutil_fchown -> fchown).
    WRAP_RE=re.compile(r'^(vsf_sysutil_|sys_|pr_fsio_|xsetuid|xsetgid)')
    wrapper_cat={}   # wrapper_func -> category (single, its primitive's)
    for wf,cats in func_effects.items():
        if WRAP_RE.match(wf):
            wrapper_cat[wf]=sorted(cats)[0]
    for fname,callees in func_callees.items():
        for callee in callees:
            if callee in wrapper_cat and not WRAP_RE.match(fname):
                func_effects[fname][wrapper_cat[callee]].add(f"via:{callee}")
    dw=dwarf_names(prog); verd=codex_verdicts(prog)
    records=[]
    for fname,cats in func_effects.items():
        if dw and fname not in dw: continue            # must be in analyzed binary
        v=verd.get(fname,"never_reviewed")
        known = v in ("true_sink","curated_positive")
        records.append({
            "program":prog,"function":fname,
            "categories":sorted(cats),
            "primitives":sorted({p for ps in cats.values() for p in ps}),
            "codex_verdict":v,
            "known_positive":known,
            "tier":"low_level_wrapper" if WRAP_RE.match(fname) else "semantic_endpoint",
            "body_span":func_span.get(fname),   # advisory: tiny span => likely thin forwarder
        })
    return records, bool(dw)


def main():
    all_recs=[]; summary=[]
    for prog,srcsub in PROGRAMS.items():
        if not (ROOT/prog/srcsub).exists():
            summary.append((prog,"NO_SOURCE",0,0,0,0)); continue
        recs,has_dw=scan_program(prog,srcsub)
        confirmed=[r for r in recs if r["known_positive"]]
        missed   =[r for r in recs if not r["known_positive"]]
        missed_nr=[r for r in missed if r["codex_verdict"]=="never_reviewed"]
        all_recs.extend(recs)
        summary.append((prog,"ok" if has_dw else "no_dwarf",len(recs),len(confirmed),
                        len(missed),len(missed_nr)))
    # write outputs
    outdir=SCANS
    (outdir/"recall_endpoint_scan.json").write_text(json.dumps(all_recs,indent=2))
    # markdown
    md=["# Recall Endpoint Scan — effect-performing functions vs codex true_sink\n",
        "Effect = final attack endpoint (privilege/exec/file-mutation/capability/mount).\n",
        "`missed` = performs an effect but NOT labeled true_sink by codex.\n",
        "| program | status | effect-funcs(in DWARF) | confirmed(true_sink) | missed | of which never_reviewed |",
        "| --- | --- | ---: | ---: | ---: | ---: |"]
    for prog,st,tot,conf,miss,mnr in summary:
        md.append(f"| {prog} | {st} | {tot} | {conf} | {miss} | {mnr} |")
    md.append("\n## Missed endpoints by program\n")
    by_prog=defaultdict(list)
    for r in all_recs:
        if not r["known_positive"]: by_prog[r["program"]].append(r)
    for prog in PROGRAMS:
        rs=sorted(by_prog.get(prog,[]),key=lambda x:(x["tier"],x["function"]))
        if not rs: continue
        md.append(f"### {prog} ({len(rs)} missed)\n")
        md.append("| function | tier | categories | primitives | codex_verdict |")
        md.append("| --- | --- | --- | --- | --- |")
        for r in rs:
            md.append(f"| `{r['function']}` | {r['tier']} | {','.join(r['categories'])} | "
                      f"{','.join(r['primitives'])} | {r['codex_verdict']} |")
        md.append("")
    # merged positive-label fragment for retraining (known + newly missed endpoints)
    pos=[{"program":r["program"],"function":r["function"],"categories":r["categories"],
          "tier":r["tier"],"label_source":"recall_scan",
          "already_known":r["known_positive"]} for r in all_recs]
    (SCANS/"recall_positive_labels.jsonl").write_text(
        "\n".join(json.dumps(x) for x in pos))
    (outdir/"RECALL_ENDPOINT_SCAN.md").write_text("\n".join(md))
    # console summary
    print(f"{'program':26s} {'status':9s} {'eff':>5s} {'conf':>5s} {'miss':>5s} {'nrev':>5s}")
    for prog,st,tot,conf,miss,mnr in summary:
        print(f"{prog:26s} {st:9s} {tot:5d} {conf:5d} {miss:5d} {mnr:5d}")
    print(f"\nwrote {outdir/'recall_endpoint_scan.json'}")
    print(f"wrote {outdir/'RECALL_ENDPOINT_SCAN.md'}")


if __name__=="__main__":
    main()
