#!/usr/bin/env python3
"""Callgraph-to-effect reachability features (step 1 of generalization fix).

The eff-call feature only fires when a function directly (or one hop) calls an
effect primitive. Most of codex's broad sinks (auth decisions, command dispatch,
transfer handlers) reach an effect only through a longer call chain, so eff_* is
0 for them and the model can't transfer cross-program.

This computes, per function, TRANSITIVE reachability to a final-effect primitive
over the intra-program call graph (built from source). Reaching is propagated to
a fixpoint, so a dispatcher that eventually leads to execve/chmod/setuid is
flagged. This subsumes wrappers and multi-hop chains automatically.

Emits ml_dataset/callgraph_reach_features.json:
  { program: { function: { reach_<cat>, reach_any, reach_ncats,
                           reach_dist, reach_neff_callees } } }
"""
from __future__ import annotations
import json, sys
from pathlib import Path
from collections import defaultdict, deque
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import recall_endpoint_scan as R   # parse_functions, EFFECT_PRIMS, PRIM_RE, CALL_RE

ROOT = R.ROOT                                  # program_targets/
REPO = ROOT.parent                             # dfb_attack_feasibility_rethink/
CATS = ["privilege_identity","capability","exec","file_mutation","mount","rlimit"]

# program -> (source roots, dwarf_facts.json). nginx lives outside program_targets.
SRC = {
 "openssh_9_7p1":          [ROOT/"openssh_9_7p1/source/openssh-9.7p1"],
 "sudo_1_8_31":            [ROOT/"sudo_1_8_31/source/sudo-1.8.31"],
 "proftpd_1_3_3c":         [ROOT/"proftpd_1_3_3c/source/proftpd-dfsg-1.3.3a"],
 "vsftpd_3_0_5":           [ROOT/"vsftpd_3_0_5/source/vsftpd-3.0.5"],
 "wu_ftpd_2_6_1":          [ROOT/"wu_ftpd_2_6_1/source/wu-ftpd-2.6.1"],
 "polkit_0_105_31":        [ROOT/"polkit_0_105_31/source/polkit-0.105"],
 "cherry_http_4b877df":    [ROOT/"cherry_http_4b877df/source/cherry"],
 "microhttpserver_4398570":[ROOT/"microhttpserver_4398570/source/MicroHttpServer"],
 "thttpd_2_29":            [ROOT/"thttpd_2_29/source/thttpd-2.29"],
 "lighttpd_1_4_59":        [ROOT/"lighttpd_1_4_59/source"],
 "dnsmasq_2_90":           [ROOT/"dnsmasq_2_90/source/dnsmasq-src"],
 "dropbear_2022_83":       [ROOT/"dropbear_2022_83/source/dropbear-src"],
 "doas_6_8_2":             [ROOT/"doas_6_8_2/source/doas-src"],
 "nginx_1_4_0_validation": [REPO.parent/"real_program/nginx140-docker/analysis_nginx140/nginx-1.4.0/src"],
}
DWARF = {p: (REPO/"nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg/dwarf_facts.json"
             if p=="nginx_1_4_0_validation"
             else ROOT/p/"artifacts/stage_02_static_ir_cfg/dwarf_facts.json")
         for p in SRC}


def dwarf_names(path: Path):
    if not path.exists(): return set()
    d = json.loads(path.read_text())
    return {v["name"] for v in d.get("functions",{}).values()
            if isinstance(v,dict) and v.get("name")}


def build_callgraph(roots):
    callees = defaultdict(set)       # func -> {callee names}
    direct  = defaultdict(set)       # func -> {effect categories called directly}
    allfns  = set()
    for root in roots:
        if not root.exists(): continue
        for cfile in root.rglob("*.c"):
            if any(p in R.SKIP_DIR for p in cfile.parts): continue
            try: funcs, lines = R.parse_functions(cfile)   # comment/string-stripped lines
            except Exception: continue
            for fn,s,e in funcs:
                allfns.add(fn)
                body = "\n".join(lines[s-1:e])
                callees[fn] |= {m.group(1) for m in R.CALL_RE.finditer(body)}
                for m in R.PRIM_RE.finditer(body):
                    direct[fn].add(R.EFFECT_PRIMS[m.group(1)])
    # restrict call edges to intra-program functions
    for fn in list(callees): callees[fn] &= allfns
    return callees, direct, allfns


def reach_fixpoint(callees, direct, allfns):
    reach = {fn:set(direct.get(fn,())) for fn in allfns}
    changed = True
    while changed:
        changed = False
        for fn in allfns:
            before = len(reach[fn])
            for c in callees.get(fn,()):
                reach[fn] |= reach.get(c,set())
            if len(reach[fn]) != before: changed = True
    return reach


def min_distance(callees, direct, allfns):
    """Reverse-BFS distance: 0 if direct effect, else hops to nearest effect."""
    rev = defaultdict(set)
    for fn,cs in callees.items():
        for c in cs: rev[c].add(fn)
    dist = {}
    dq = deque()
    for fn in allfns:
        if direct.get(fn): dist[fn]=0; dq.append(fn)
    while dq:
        u = dq.popleft()
        for p in rev.get(u,()):
            if p not in dist:
                dist[p] = dist[u]+1; dq.append(p)
    return dist


def main():
    out = {}
    for prog, roots in SRC.items():
        callees, direct, allfns = build_callgraph(roots)
        if not allfns:
            print(f"{prog:24s} NO SOURCE"); continue
        reach = reach_fixpoint(callees, direct, allfns)
        dist = min_distance(callees, direct, allfns)
        dw = dwarf_names(DWARF[prog])
        feats = {}
        for fn in allfns:
            if dw and fn not in dw: continue
            rc = reach[fn]
            if not rc: continue   # only emit functions that can reach an effect
            neff = sum(1 for c in callees.get(fn,()) if reach.get(c) or direct.get(c))
            row = {f"reach_{c}": int(c in rc) for c in CATS}
            row["reach_any"]=1
            row["reach_ncats"]=len(rc)
            row["reach_dist"]=int(dist.get(fn,99))
            row["reach_neff_callees"]=int(neff)
            feats[fn]=row
        out[prog]=feats
        print(f"{prog:24s} funcs={len(allfns):5d}  effect-reaching(in DWARF)={len(feats):5d}")
    (R.ROOT/"ml_dataset"/"callgraph_reach_features.json").write_text(json.dumps(out,indent=2))
    print("wrote ml_dataset/callgraph_reach_features.json")


if __name__=="__main__":
    main()
