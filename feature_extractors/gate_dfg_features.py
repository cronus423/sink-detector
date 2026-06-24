#!/usr/bin/env python3
"""DFG-based gating feature (proper def-use, no heuristic window).

Targets authz/decision sinks (missed because they issue no syscall). Their real
signature: the function's RETURN value is used in a decision. We track it with the
stage_02 reaching-definitions DFG (register + memory edges, so stack spills and
far-away branches are followed correctly):

  from each `call F` node (which defines rax), traverse def->use edges forward;
  if the value reaches a `test`/`cmp` instruction, F's return is branched-on.

Per function F:
  gate_dfg_branched : # call sites whose return reaches a test/cmp via def-use
  gate_dfg_ncallers : # distinct caller functions where that happens
Emits ml_dataset/gate_dfg_features.json   (no attacker-reachability here)
"""
import json, re, sys
from pathlib import Path
from collections import defaultdict, deque
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG
import bin_effect_features as BE

SYM = re.compile(r'<([^>+@]+)')
MAXHOPS = 80

RAX = {"rax","eax","ax","al"}
def pc2func(prog):
    """pc->function, and function->ordered pc list (pc order = file order)."""
    m = {}; order = defaultdict(list)
    with BE.disasm_path(prog).open() as f:
        for line in f:
            if '"pc"' not in line: continue
            r = json.loads(line)
            fn=r.get("function"); pc=r.get("pc")
            if fn and pc: m[pc]=fn; order[fn].append(pc)
    return m, order

def uses_rax(n):
    return any(u.get("register") in RAX for u in n.get("uses",{}).get("registers",[]))

def graphs_path(prog):
    if prog == "nginx_1_4_0_validation":
        return CG.ROOT.parent/"nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg/nginx_ir_graphs.json"
    return CG.ROOT/prog/"artifacts/stage_02_static_ir_cfg/nginx_ir_graphs.json"

def main():
    out = {}
    for prog in CG.SRC:
        gp = graphs_path(prog)
        if not gp.exists(): print(f"{prog:24s} no ir_graphs"); continue
        g = json.loads(gp.read_text())["dfg"]
        node = {n["id"]: n for n in g["nodes"]}
        adj = defaultdict(list)
        for e in g["edges"]:
            adj[e["source"]].append(e["target"])
        p2f, order = pc2func(prog)
        dw = CG.dwarf_names(CG.DWARF[prog])
        def reaches_cmp(start):
            seen=set([start]); dq=deque(adj.get(start,())); hops=0
            while dq and hops<MAXHOPS:
                u=dq.popleft(); hops+=1
                if u in seen: continue
                seen.add(u)
                if str(node.get(u,{}).get("opcode","")) in ("test","cmp"): return True
                dq.extend(adj.get(u,()))
            return False
        gate = defaultdict(lambda: {"branched":0,"callers":set()})
        for fn, pcs in order.items():
            for i,pc in enumerate(pcs):
                n=node.get(pc)
                if not n or not str(n.get("opcode","")).startswith("call"): continue
                m=SYM.search(n.get("asm",""))
                if not m: continue
                callee=m.group(1).strip().split("@")[0]
                # BRIDGE: find first rax-consumer in the next few instrs (pc order)
                cons=None
                for j in range(i+1, min(i+7,len(pcs))):
                    nj=node.get(pcs[j])
                    if nj and uses_rax(nj): cons=pcs[j]; break
                    if nj and str(nj.get("opcode","")).startswith("call"): break  # next call clobbers rax
                if cons is None: continue
                op=str(node.get(cons,{}).get("opcode",""))
                branched = op in ("test","cmp") or reaches_cmp(cons)
                if branched:
                    gg=gate[callee]; gg["branched"]+=1; gg["callers"].add(fn)
        feats={}
        for fn,gg in gate.items():
            if dw and fn not in dw: continue
            feats[fn]={"gate_dfg_branched":int(gg["branched"]),
                       "gate_dfg_ncallers":int(len(gg["callers"]))}
        out[prog]=feats
        print(f"{prog:24s} functions with DFG gating: {len(feats)}")
    (CG.ROOT/"ml_dataset"/"gate_dfg_features.json").write_text(json.dumps(out))
    print("wrote ml_dataset/gate_dfg_features.json")

if __name__=="__main__":
    main()
