#!/usr/bin/env python3
"""Binary-grounded callgraph-to-effect reachability (replaces the source version).

Per the architecture rule: feature/semantic extraction must come from the BINARY
(with DWARF), not source. The call graph is built from the disassembly's direct
`call ... <name>` edges; effect primitives are detected as call targets; transitive
reachability is propagated to a fixpoint. Same schema as callgraph_reach_features.

Emits ml_dataset/bin_reach_features.json  { program: { func: {reach_*} } }
"""
import json, re, sys
from pathlib import Path
from collections import defaultdict, deque
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG
import bin_effect_features as BE   # reuse EFFECT map + disasm_path

CATS = ["privilege_identity","capability","exec","file_mutation","mount","rlimit","file_read"]
SYM = re.compile(r'<([^>+@]+)')

def build(prog):
    callees = defaultdict(set); direct = defaultdict(set); allfns = set()
    for p in BE.disasm_paths(prog):
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
            cat = BE.EFFECT.get(tgt)
            if cat: direct[fn].add(cat)
            if tgt in BE.FILEREAD: direct[fn].add("file_read")   # dual: open* is also file_mutation
            if not cat and tgt not in BE.FILEREAD:
                callees[fn].add(tgt)                              # internal-call edge
    for fn in list(callees): callees[fn] &= allfns
    return callees, direct, allfns

def reach_fixpoint(callees, direct, allfns):
    reach = {fn:set(direct.get(fn,())) for fn in allfns}
    changed = True
    while changed:
        changed = False
        for fn in allfns:
            b=len(reach[fn])
            for c in callees.get(fn,()): reach[fn] |= reach.get(c,set())
            if len(reach[fn])!=b: changed=True
    return reach

def min_dist(callees, direct, allfns):
    rev=defaultdict(set)
    for fn,cs in callees.items():
        for c in cs: rev[c].add(fn)
    dist={}; dq=deque()
    for fn in allfns:
        if direct.get(fn): dist[fn]=0; dq.append(fn)
    while dq:
        u=dq.popleft()
        for p in rev.get(u,()):
            if p not in dist: dist[p]=dist[u]+1; dq.append(p)
    return dist

def main():
    out={}
    for prog in CG.SRC:
        if not BE.disasm_paths(prog): continue
        callees,direct,allfns = build(prog)
        reach = reach_fixpoint(callees,direct,allfns); dist=min_dist(callees,direct,allfns)
        dw = BE.dwarf_names_all(prog)
        feats={}
        for fn in allfns:
            if dw and fn not in dw: continue
            rc=reach[fn]
            if not rc: continue
            neff=sum(1 for c in callees.get(fn,()) if reach.get(c) or direct.get(c))
            row={f"reach_{c}":int(c in rc) for c in CATS}
            row["reach_any"]=1; row["reach_ncats"]=len(rc)
            row["reach_dist"]=int(dist.get(fn,99)); row["reach_neff_callees"]=int(neff)
            feats[fn]=row
        out[prog]=feats
        print(f"{prog:24s} effect-reaching (binary, in DWARF): {len(feats)}")
    (CG.ROOT/"ml_dataset"/"bin_reach_features.json").write_text(json.dumps(out,indent=2))
    print("wrote ml_dataset/bin_reach_features.json")

if __name__=="__main__":
    main()
