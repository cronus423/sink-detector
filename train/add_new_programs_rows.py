#!/usr/bin/env python3
"""Data augmentation: append tinyhttpd + gophernicus (real fopen/fread-serving
programs) to the integrated dataset, to supply non-open() file-read-serve sink
positives the model lacked (the 53:2 imbalance).

Assembles full 158-col rows: base(125 CFG) + classic eff/reach + string(with the
immediate-mov fix) + p_nparam/p_nptr + eff_file_read + reach_file_read +
fr_computed_path. Reuses build_integrated_dataset/build_curated for the base and
classic eff/reach; computes the file_read/string/provenance features from the
stage_02 disassembly directly (same logic as the other train/ scripts).
Idempotent: removes prior rows for these two programs first.
"""
import csv, json, re, sys
from pathlib import Path
from collections import defaultdict
SCRIPTS=Path(__file__).resolve().parent
sys.path.insert(0,str(SCRIPTS))
import build_curated_function_feature_dataset as B
import build_integrated_dataset as I

REL=SCRIPTS.parent
ROOT=Path("/home/peiyao/program/LLM_AUTO_DOP/dfb_attack_feasibility_rethink/program_targets")

NEW={
 "tinyhttpd_jdb":{
   "pos":["serve_file","execute_cgi"],
   "neg":["accept_request","cat","get_line","headers","not_found","bad_request",
          "unimplemented","cannot_execute","startup","error_die","main"]},
 "gophernicus_3_1":{
   "pos":["send_text_file","send_binary_file","run_cgi"],
   "neg":["gopher_file","gopher_filetype","gopher_menu","gophermap","selector_to_path",
          "setenv_cgi","chomp","html_encode","strlcpy","strlcat","strreplace","strcut",
          "parse_args","init_state","footer","sortdir","info","strfsize","url_redirect",
          "server_status"]},
}

# ---- file_read / string / provenance from disassembly (mirror train/ scripts) ----
SYM=re.compile(r'<([^>+@]+)')
FILEREAD=set("""read pread pread64 readv preadv fread fread_unlocked fgets fgets_unlocked
fgetc getc getc_unlocked getline getdelim fscanf __isoc99_fscanf mmap mmap64 sendfile
sendfile64 opendir fdopendir readdir readdir64 readdir_r scandir scandir64 fopen fopen64
freopen freopen64 fdopen open open64 openat openat64""".split())
PATHREG={"open":"rdi","open64":"rdi","fopen":"rdi","fopen64":"rdi","freopen":"rdi",
         "opendir":"rdi","scandir":"rdi","openat":"rsi","openat64":"rsi"}
PARAM_REGS={"rdi","rsi","rdx","rcx","r8","r9"}
ALLREG={"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"}
ALIAS={"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi","ebp":"rbp","esp":"rsp",
 "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13","r14d":"r14","r15d":"r15"}
def nrm(r): return ALIAS.get(r,r)
RIP=re.compile(r'\[rip([+-]0x[0-9a-fA-F]+)\]'); IMM=re.compile(r',\s*(0x[0-9a-fA-F]{7,16})\b')
import subprocess
PAT_SYS=re.compile(r'^/(etc|var|tmp|usr|bin|sbin|dev|proc|lib|root)\b|^/[a-z]+/')
PAT_SH=re.compile(r'/bin/sh|/bin/bash|(^|/)(sh|bash|dash)$')
PAT_CR=re.compile(r'uid|gid|user|passwd|shadow|root|group|privile|cred|login|setuid',re.I)
PAT_CAP=re.compile(r'cap_|chroot|capab|keepcap',re.I)

def disasm(p): return ROOT/p/"artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"
def binpath(p):
    d=ROOT/p/"target"
    return max((f for f in d.rglob("*") if f.is_file() and f.read_bytes()[:4]==b"\x7fELF"),
               key=lambda f:f.stat().st_size)
def imm_str(h):
    v=int(h,16); b=v.to_bytes((len(h)-1)//2,"little").split(b"\x00",1)[0]
    return b.decode("ascii") if len(b)>=3 and all(32<=c<127 for c in b) else None
def sections(elf):
    out=[]
    for ln in subprocess.run(["objdump","-h",str(elf)],capture_output=True,text=True).stdout.splitlines():
        q=ln.split()
        if len(q)>=7 and q[0].isdigit(): out.append((q[1],int(q[3],16),int(q[2],16),int(q[5],16)))
    return out
def resolve(data,secs,va):
    for nm,vma,sz,off in secs:
        if vma<=va<vma+sz and nm.startswith((".rodata",".data.rel.ro")):
            fo=off+(va-vma); e=data.find(b"\x00",fo,fo+200)
            if e<0: return None
            try: s=data[fo:e].decode("ascii")
            except: return None
            return s if len(s)>=3 and all(32<=ord(c)<127 for c in s) else None
    return None

def per_prog(prog):
    funcs=defaultdict(list)
    for l in disasm(prog).open():
        r=json.loads(l); fn=r.get("function")
        if fn and fn not in(".plt",".plt.sec"): funcs[fn].append(r)
    elf=binpath(prog); data=elf.read_bytes(); secs=sections(elf)
    # eff_file_read + call graph for reach
    callees=defaultdict(set); direct=defaultdict(int); allfns=set(funcs)
    frdir=defaultdict(int); strs=defaultdict(list); comp=defaultdict(int)
    for fn,insns in funcs.items():
        for i,r in enumerate(insns):
            ins=r.get("instruction","")
            if "rip" in ins:
                m=RIP.search(ins)
                if m:
                    try: t=int(r["pc"],16)+r.get("size",0)+int(m.group(1),16); s=resolve(data,secs,t)
                    except: s=None
                    if s: strs[fn].append(s)
            if ins.startswith("mov"):
                mi=IMM.search(ins)
                if mi:
                    s=imm_str(mi.group(1))
                    if s: strs[fn].append(s)
            if ins.startswith("call"):
                m=SYM.search(ins)
                if not m: continue
                tgt=m.group(1).strip()
                if tgt in FILEREAD: frdir[fn]+=1
                else: callees[fn].add(tgt)
                preg=PATHREG.get(tgt)
                if preg:
                    reg=preg
                    for k in range(i-1,max(-1,i-40),-1):
                        mm=re.match(r'(\w+)\s+([^,]+?)(?:,(.*))?$',insns[k].get("instruction",""))
                        if not mm: continue
                        op,dst,src=mm.group(1),mm.group(2).strip(),(mm.group(3)or"").strip()
                        if nrm(dst)!=reg: continue
                        if op=="lea": cls="const" if "[rip" in src else "computed"; break
                        if op=="mov":
                            if re.match(r'^-?0x',src): cls="const"; break
                            if nrm(src) in ALLREG: reg=nrm(src); continue
                            cls="computed"; break
                        cls="computed"; break
                    else: cls="param" if reg in PARAM_REGS else "unknown"
                    if cls in("computed","param"): comp[fn]+=1
    for fn in list(callees): callees[fn]&=allfns
    reach={fn:(1 if frdir.get(fn) else 0) for fn in allfns}
    ch=True
    while ch:
        ch=False
        for fn in allfns:
            if reach[fn]: continue
            for c in callees.get(fn,()):
                if reach.get(c): reach[fn]=1; ch=True; break
    def sfeat(ls):
        return {"s_count":min(len(ls),50),"s_path":int(any('/' in x for x in ls)),
          "s_syspath":int(any(PAT_SYS.search(x) for x in ls)),"s_shell":int(any(PAT_SH.search(x) for x in ls)),
          "s_cred":int(any(PAT_CR.search(x) for x in ls)),"s_cap":int(any(PAT_CAP.search(x) for x in ls)),
          "s_fmt":int(any('%s' in x or '%d' in x for x in ls))}
    return {"eff_file_read":dict(frdir),"reach_file_read":reach,"fr_computed_path":dict(comp),
            "s":{fn:sfeat(ls) for fn,ls in strs.items()}}

def main():
    csv_path=REL/"dataset"/"integrated_function_features.csv"
    rows=list(csv.DictReader(open(csv_path))); header=list(rows[0].keys())
    rows=[r for r in rows if r["target_id"] not in NEW]         # idempotent
    added=0
    for tgt,lab in NEW.items():
        stage02=ROOT/tgt/"artifacts"/"stage_02_static_ir_cfg"
        cfg=B.load_cfg_functions_from_dir(stage02)
        dw={v["name"] for v in json.loads((stage02/"dwarf_facts.json").read_text())["functions"].values()
            if isinstance(v,dict) and v.get("name")}
        X=per_prog(tgt)
        for y,fns in ((1,lab["pos"]),(0,lab["neg"])):
            for fn in fns:
                if fn not in cfg or fn not in dw:
                    print(f"  SKIP {tgt}:{fn} (not in cfg/dwarf)"); continue
                d={"target_id":tgt,"function":fn,"y":y}
                d.update(B.extract_binary_features(cfg[fn], I.STRICT))
                d.update(I.eff_feats(tgt,fn)); d.update(I.reach_feats(tgt,fn)); d.update(I.st_feats(tgt,fn))
                d.update(X["s"].get(fn,{"s_count":0,"s_path":0,"s_syspath":0,"s_shell":0,"s_cred":0,"s_cap":0,"s_fmt":0}))
                d["eff_file_read"]=X["eff_file_read"].get(fn,0)
                d["reach_file_read"]=X["reach_file_read"].get(fn,0)
                d["fr_computed_path"]=X["fr_computed_path"].get(fn,0)
                rows.append({k:d.get(k,0) for k in header}); added+=1
        print(f"{tgt}: +{len(lab['pos'])} pos / +{len(lab['neg'])} neg")
    with open(csv_path,"w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=header); w.writeheader(); w.writerows(rows)
    print(f"appended {added} rows; dataset now {len(rows)} rows, {sum(1 for r in rows if str(r['y']) in('1','1.0'))} positives")

if __name__=="__main__":
    main()
