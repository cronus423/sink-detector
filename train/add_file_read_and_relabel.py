#!/usr/bin/env python3
"""Step 2 of the file-read-sink improvement.

Adds a new binary effect feature `file_read` (content-disclosure reads) and applies
the verified file-read-sink relabeling, then leaves retraining to train_final.py.

WHY: the existing effect taxonomy lumps open()/openat() into `file_mutation` and
has NO category for the pure read/serve primitives (read/pread/fread/fgets/mmap/
sendfile/opendir/readdir/fopen). So a function that only reads-and-serves a file
(e.g. microhttpserver `_ReadStaticFiles` via fopen+fread) gets every eff_*=0 and
is invisible to the model. This script computes, straight from the stage_02
disassembly (same method as bin_effect_features.py):
  eff_file_read    : # direct calls to read/serve primitives in the function
  reach_file_read  : transitively reaches such a primitive (covers wrapper-chain
                     sinks like handle_retr/xfer_retr/ngx_open_and_stat_file whose
                     open lives one hop down)
and injects both columns into dataset/integrated_function_features.csv (training)
and data/all_function_features.csv (inference). It then applies the relabeling
from the step-1 ground-truth audit (8 adds + 3 thin-wrapper demotions) and adds
the 2 file-read sinks that were absent from the labeled subset.

Idempotent-ish: run once on the pristine CSVs (a .backup_pre_fileread/ exists).
"""
import csv, json, re
from pathlib import Path
from collections import defaultdict

REL  = Path(__file__).resolve().parents[1]
ROOT = Path("/home/peiyao/program/LLM_AUTO_DOP/dfb_attack_feasibility_rethink/program_targets")
REPO = ROOT.parent

# read/serve primitives = content disclosure. open* included (read-opens) even
# though open* is ALSO file_mutation; a function can be both.
FILEREAD = set("""read pread pread64 readv preadv fread fread_unlocked fgets
fgets_unlocked fgetc getc getc_unlocked getline getdelim fscanf __isoc99_fscanf
mmap mmap64 sendfile sendfile64 opendir fdopendir readdir readdir64 readdir_r
scandir scandir64 fopen fopen64 freopen freopen64 fdopen open open64 openat
openat64""".split())
SYM = re.compile(r'<([^>+@]+)')

def disasm(prog):
    if prog == "nginx_1_4_0_validation":
        return REPO/"nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"
    return ROOT/prog/"artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"

def compute(prog):
    """-> {fn: (eff_file_read_count, reach_file_read 0/1)} for one program."""
    p = disasm(prog)
    if not p.exists():
        return {}
    callees = defaultdict(set); direct = defaultdict(int); allfns = set()
    with p.open() as f:
        for line in f:
            if "call" not in line: continue
            r = json.loads(line); fn = r.get("function"); ins = r.get("instruction","")
            if not fn or fn in (".plt",".plt.sec"): continue
            allfns.add(fn)
            if not ins.startswith("call"): continue
            m = SYM.search(ins)
            if not m: continue
            tgt = m.group(1).strip()
            if tgt in FILEREAD: direct[fn] += 1
            else:               callees[fn].add(tgt)
    for fn in list(callees): callees[fn] &= allfns
    reach = {fn:(1 if direct.get(fn) else 0) for fn in allfns}
    changed = True
    while changed:
        changed = False
        for fn in allfns:
            if reach[fn]: continue
            for c in callees.get(fn, ()):
                if reach.get(c): reach[fn] = 1; changed = True; break
    return {fn:(direct.get(fn,0), reach.get(fn,0)) for fn in allfns}

# ---- verified relabeling from the step-1 ground-truth audit ----
RELABEL = {
    # ADD file-read sinks (were y=0)
    ("microhttpserver_4398570","_ReadStaticFiles"): "1",
    ("wu_ftpd_2_6_1","retrieve"):                    "1",
    ("vsftpd_3_0_5","handle_retr"):                  "1",
    ("proftpd_1_3_3c","xfer_retr"):                  "1",
    ("openssh_9_7p1","process_read"):                "1",
    ("nginx_1_4_0_validation","ngx_open_and_stat_file"): "1",
    # DEMOTE thin-wrapper granularity mislabels (were y=1)
    ("nginx_1_4_0_validation","ngx_open_file_wrapper"): "0",  # thin open() wrapper
    ("proftpd_1_3_3c","sys_open"):                      "0",  # generic FSIO backend
    ("lighttpd_1_4_59","stream_open"):                  "0",  # reads OWN config only
}
# file-read sinks absent from the labeled subset -> add as new positive rows
NEW_SINKS = [("lighttpd_1_4_59","http_response_send_file"),
             ("thttpd_2_29","ls")]

def main():
    progs = sorted({disasm_prog for disasm_prog in [
        "cherry_http_4b877df","dnsmasq_2_90","doas_6_8_2","dropbear_2022_83",
        "lighttpd_1_4_59","microhttpserver_4398570","nginx_1_4_0_validation",
        "openssh_9_7p1","polkit_0_105_31","proftpd_1_3_3c","sudo_1_8_31",
        "thttpd_2_29","vsftpd_3_0_5","wu_ftpd_2_6_1"]})
    feats = {}
    for prog in progs:
        for fn,(e,rc) in compute(prog).items():
            feats[(prog,fn)] = (e,rc)
    print(f"computed file_read features for {len(feats)} (prog,fn) pairs")

    # base rate sanity
    tot=len(feats); de=sum(1 for v in feats.values() if v[0]>0); dr=sum(1 for v in feats.values() if v[1])
    print(f"  eff_file_read>0: {de}/{tot} ({de/tot:.1%}) | reach_file_read=1: {dr}/{tot} ({dr/tot:.1%})")

    # ---- patch data/all_function_features.csv ----
    aff_path = REL/"data"/"all_function_features.csv"
    aff = list(csv.DictReader(open(aff_path)))
    aff_fields = list(aff[0].keys())
    for c in ("eff_file_read","reach_file_read"):
        if c not in aff_fields: aff_fields.append(c)
    for r in aff:
        e,rc = feats.get((r["target_id"],r["function"]),(0,0))
        r["eff_file_read"]=e; r["reach_file_read"]=rc
    with open(aff_path,"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=aff_fields); w.writeheader(); w.writerows(aff)
    affmap = {(r["target_id"],r["function"]):r for r in aff}
    print(f"patched all_function_features.csv ({len(aff)} rows, +2 cols)")

    # ---- patch dataset/integrated_function_features.csv ----
    ds_path = REL/"dataset"/"integrated_function_features.csv"
    ds = list(csv.DictReader(open(ds_path)))
    base_cols = [c for c in ds[0].keys() if c not in ("target_id","function","y")]
    ds_fields = ["target_id","function","y"] + base_cols + ["eff_file_read","reach_file_read"]
    for r in ds:
        e,rc = feats.get((r["target_id"],r["function"]),(0,0))
        r["eff_file_read"]=e; r["reach_file_read"]=rc
    # add the 2 missing file-read sinks, pulling base cols from all_function_features
    existing=set((r["target_id"],r["function"]) for r in ds)
    added=0
    for tid,fn in NEW_SINKS:
        if (tid,fn) in existing: continue
        src=affmap[(tid,fn)]
        nr={"target_id":tid,"function":fn,"y":"1"}
        for c in base_cols: nr[c]=src[c]
        e,rc=feats.get((tid,fn),(0,0)); nr["eff_file_read"]=e; nr["reach_file_read"]=rc
        ds.append(nr); added+=1
    # apply relabels
    nrl=0
    for r in ds:
        k=(r["target_id"],r["function"])
        if k in RELABEL and r["y"]!=RELABEL[k]:
            r["y"]=RELABEL[k]; nrl+=1
    with open(ds_path,"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=ds_fields); w.writeheader(); w.writerows(ds)
    npos=sum(1 for r in ds if r["y"] in ("1","1.0"))
    print(f"patched integrated dataset: {len(ds)} rows (+{added} new sink rows), "
          f"{nrl} relabels applied, {npos} positives total")

if __name__=="__main__":
    main()
