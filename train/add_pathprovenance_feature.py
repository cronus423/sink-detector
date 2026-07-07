#!/usr/bin/env python3
"""Step 4: add the path-provenance dataflow feature `fr_computed_path`.

For each call to a path-taking read primitive (open/openat/fopen/opendir/scandir),
a bounded backward register slice classifies the PATH argument as:
  - const    : `lea REG,[rip+..]` / immediate -> a fixed rodata path (own config)
  - computed : stack buffer / memory load / an incoming parameter register
               -> the path is derived from input (attacker-influenceable)
`fr_computed_path` = # of read-opens with a computed/param-derived path.

This is the clean signal that distinguishes microhttpserver `_ReadStaticFiles`
(fopen of a URI-derived stack path) from a benign config reader (fopen of a rodata
constant): it fires on 12% of sinks but only 1% of non-sinks, vs raw eff_file_read's
3%. Patches both CSVs. Note: intraprocedural only (wrapper-chain sinks whose open
lives one hop down get 0 here; interprocedural propagation is a future extension).
"""
import csv, json, re
from pathlib import Path
from collections import defaultdict

REL  = Path(__file__).resolve().parents[1]
ROOT = Path("/home/peiyao/program/LLM_AUTO_DOP/dfb_attack_feasibility_rethink/program_targets")
REPO = ROOT.parent

SYM=re.compile(r'<([^>+@]+)')
PATHREG={"open":"rdi","open64":"rdi","fopen":"rdi","fopen64":"rdi","freopen":"rdi",
         "opendir":"rdi","scandir":"rdi","openat":"rsi","openat64":"rsi"}
PARAM_REGS={"rdi","rsi","rdx","rcx","r8","r9"}
ALLREG={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"}
ALIAS={"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi","ebp":"rbp",
       "esp":"rsp","r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13",
       "r14d":"r14","r15d":"r15"}
def norm(r): return ALIAS.get(r,r)

def disasm(prog):
    if prog=="nginx_1_4_0_validation":
        return REPO/"nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"
    return ROOT/prog/"artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"

def classify(insns, ci, preg):
    reg=preg
    for k in range(ci-1, max(-1,ci-40), -1):
        m=re.match(r'(\w+)\s+([^,]+?)(?:,(.*))?$', insns[k])
        if not m: continue
        op,dst,src=m.group(1),m.group(2).strip(),(m.group(3) or "").strip()
        if norm(dst)!=reg: continue
        if op=="lea":
            return "const" if "[rip" in src else "computed"
        if op=="mov":
            if re.match(r'^-?0x',src): return "const"
            sreg=norm(src)
            if sreg in ALLREG: reg=sreg; continue
            return "computed"
        return "computed"
    return "param" if reg in PARAM_REGS else "unknown"

def compute(prog):
    p=disasm(prog)
    if not p.exists(): return {}
    funcs=defaultdict(list)
    for l in p.open():
        r=json.loads(l); fn=r.get("function")
        if fn and fn not in(".plt",".plt.sec"): funcs[fn].append(r.get("instruction",""))
    out={}
    for fn,insns in funcs.items():
        comp=0
        for i,ins in enumerate(insns):
            if not ins.startswith("call"): continue
            m=SYM.search(ins)
            if not m: continue
            preg=PATHREG.get(m.group(1).strip())
            if preg and classify(insns,i,preg) in ("computed","param"): comp+=1
        out[fn]=comp
    return out

def main():
    progs=["cherry_http_4b877df","dnsmasq_2_90","doas_6_8_2","dropbear_2022_83","lighttpd_1_4_59",
           "microhttpserver_4398570","nginx_1_4_0_validation","openssh_9_7p1","polkit_0_105_31",
           "proftpd_1_3_3c","sudo_1_8_31","thttpd_2_29","vsftpd_3_0_5","wu_ftpd_2_6_1"]
    FR={}
    for p in progs:
        for fn,c in compute(p).items(): FR[(p,fn)]=c
    for path in (REL/"dataset"/"integrated_function_features.csv", REL/"data"/"all_function_features.csv"):
        rows=list(csv.DictReader(open(path))); fields=list(rows[0].keys())
        if "fr_computed_path" not in fields: fields.append("fr_computed_path")
        for r in rows: r["fr_computed_path"]=FR.get((r["target_id"],r["function"]),0)
        with open(path,"w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
        print(f"patched {path.name}: +fr_computed_path")

if __name__=="__main__":
    main()
