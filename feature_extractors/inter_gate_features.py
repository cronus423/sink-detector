#!/usr/bin/env python3
"""Inter-procedural GATING features (targets the authz/decision FN class).

An authz/authentication sink decides allow/deny but issues no syscall, so eff/
reach features miss it. Its real signature is inter-procedural: its RETURN VALUE
is branched on by callers, and that branch guards a path that reaches an effect
( if (auth_check(...)) { do_exec(); } ). All binary-derived from the disassembly.

Per function F:
  gate_branched   : # call sites where caller does `call F; test/cmp <ret>; jCC`
  gate_eff_caller : 1 if any such branching caller itself reaches an effect
  gate_ncallers   : # distinct callers that branch on F's return
Emits ml_dataset/inter_gate_features.json
"""
import json, re, sys
from pathlib import Path
from collections import defaultdict
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG
import bin_effect_features as BE

SYM = re.compile(r'<([^>+@]+)')
RETREG = re.compile(r'\b(rax|eax|ax|al)\b')
JCC = re.compile(r'^j(?!mp)\w+')   # conditional jump (not jmp)

def load_func_instrs(prog):
    """ordered (opcode, instr_text, callee) per function."""
    p = BE.disasm_path(prog)
    funcs = defaultdict(list)
    with p.open() as f:
        for line in f:
            if '"function"' not in line: continue
            r = json.loads(line); fn = r.get("function"); ins = r.get("instruction","")
            if not fn or fn in (".plt",".plt.sec"): continue
            op = ins.split()[0] if ins else ""
            callee = None
            if op.startswith("call"):
                m = SYM.search(ins); callee = m.group(1).strip() if m else None
            funcs[fn].append((op, ins, callee))
    return funcs

def main():
    # caller reaches effect? use binary reach set
    reachset = {p: set(json.loads((CG.ROOT/"ml_dataset"/"bin_reach_features.json").read_text()).get(p,{}))
                for p in CG.SRC}
    out = {}
    for prog in CG.SRC:
        if not BE.disasm_path(prog).exists(): continue
        funcs = load_func_instrs(prog)
        dw = CG.dwarf_names(CG.DWARF[prog])
        gate = defaultdict(lambda: {"branched":0,"callers":set(),"eff_caller":0})
        SLOT = re.compile(r'(\[(?:rbp|rsp|rbx)[+\-]0x[0-9a-f]+\])')
        MOVRET = re.compile(r'^mov\s+(\[[^\]]+\]|r\w+|e\w+),\s*(rax|eax|ax|al)$')
        for caller, instrs in funcs.items():
            for i,(op,ins,callee) in enumerate(instrs):
                if not (op.startswith("call") and callee): continue
                branched=False
                # case A: immediate test/cmp on ret-reg + jCC within 3
                win = instrs[i+1:i+4]
                if any(w[0] in ("test","cmp") and RETREG.search(w[1]) for w in win) and \
                   any(JCC.match(w[0]) for w in win):
                    branched=True
                else:
                    # case B: return spilled to a slot/reg, branched on later
                    dest=None
                    m=MOVRET.match(instrs[i+1][1]) if i+1<len(instrs) else None
                    if m: dest=m.group(1)
                    if dest:
                        for j in range(i+2, min(i+50,len(instrs))):
                            if JCC.match(instrs[j][0]):
                                ctx=" ".join(instrs[k][1] for k in range(max(i+2,j-3),j))
                                if dest in ctx or (dest.startswith('[') and dest in ctx):
                                    branched=True; break
                if branched:
                    g = gate[callee]; g["branched"]+=1; g["callers"].add(caller)
                    if caller in reachset.get(prog,set()): g["eff_caller"]=1
        feats={}
        for fn,g in gate.items():
            if dw and fn not in dw: continue
            feats[fn]={"gate_branched":int(g["branched"]),
                       "gate_ncallers":int(len(g["callers"])),
                       "gate_eff_caller":int(g["eff_caller"])}
        out[prog]=feats
        print(f"{prog:24s} functions with gating signal: {len(feats)}")
    (CG.ROOT/"ml_dataset"/"inter_gate_features.json").write_text(json.dumps(out))
    print("wrote ml_dataset/inter_gate_features.json")

if __name__=="__main__":
    main()
