#!/usr/bin/env python3
"""Step 3a: recompute the s_* string features WITH stack-immediate string
reconstruction, and patch both CSVs in place.

The rip-relative string extractor was blind to strings that small servers
stack-initialize via immediate movs (e.g. microhttpserver builds "static/" and
its HTTP header as `movabs rax,0x2f636974617473` etc. — no rodata reference).
That left `_ReadStaticFiles` with s_path=0 and no corroborating signal beyond
eff_file_read, so it could not transfer cross-program. This mirrors the enhanced
feature_extractors/bin_string_features.py but runs self-contained (the bundled
extractor's import chain lives in the repo scripts/ dir).

Recomputes s_count/s_path/s_syspath/s_shell/s_cred/s_cap/s_fmt for every
(program, function) present in the CSVs and overwrites those columns.
"""
import csv, json, re, subprocess
from pathlib import Path
from collections import defaultdict

REL  = Path(__file__).resolve().parents[1]
ROOT = Path("/home/peiyao/program/LLM_AUTO_DOP/dfb_attack_feasibility_rethink/program_targets")
REPO = ROOT.parent

RIP = re.compile(r'\[rip([+-]0x[0-9a-fA-F]+)\]')
IMM = re.compile(r',\s*(0x[0-9a-fA-F]{7,16})\b')
PAT_SYS = re.compile(r'^/(etc|var|tmp|usr|bin|sbin|dev|proc|lib|root)\b|^/[a-z]+/')
PAT_SH  = re.compile(r'/bin/sh|/bin/bash|(^|/)(sh|bash|dash)$')
PAT_CR  = re.compile(r'uid|gid|user|passwd|shadow|root|group|privile|cred|login|setuid', re.I)
PAT_CAP = re.compile(r'cap_|chroot|capab|keepcap', re.I)

def disasm(prog):
    if prog == "nginx_1_4_0_validation":
        return REPO/"nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"
    return ROOT/prog/"artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"

def binpath(prog):
    d = REPO/"nginx_1_4_0_validation/target" if prog=="nginx_1_4_0_validation" else ROOT/prog/"target"
    if not d.exists(): return None
    elfs=[]
    for p in d.rglob("*"):
        if p.is_file() and (p.stat().st_mode & 0o111) and p.suffix not in (".sh",".so",".md",".json"):
            try:
                if p.read_bytes()[:4]==b"\x7fELF": elfs.append(p)
            except OSError: pass
    return max(elfs, key=lambda p:p.stat().st_size) if elfs else None

def load_sections(elf):
    out=[]
    for line in subprocess.run(["objdump","-h",str(elf)],capture_output=True,text=True).stdout.splitlines():
        p=line.split()
        if len(p)>=7 and p[0].isdigit():
            out.append((p[1],int(p[3],16),int(p[2],16),int(p[5],16)))
    return out

def resolve(data, sections, vaddr):
    for name,vma,size,off in sections:
        if vma<=vaddr<vma+size and name.startswith((".rodata",".data.rel.ro")):
            fo=off+(vaddr-vma); end=data.find(b"\x00",fo,fo+200)
            if end<0: return None
            try: s=data[fo:end].decode("ascii")
            except UnicodeDecodeError: return None
            return s if len(s)>=3 and all(32<=ord(c)<127 for c in s) else None
    return None

def imm_string(h):
    v=int(h,16); nb=(len(h)-2+1)//2
    try: b=v.to_bytes(nb,"little")
    except OverflowError: return None
    b=b.split(b"\x00",1)[0]
    if len(b)>=3 and all(32<=c<127 for c in b): return b.decode("ascii")
    return None

def strings_for(prog):
    elf=binpath(prog); dp=disasm(prog)
    if not elf or not dp.exists(): return {}
    data=elf.read_bytes(); secs=load_sections(elf)
    strs=defaultdict(list)
    with dp.open() as f:
        for line in f:
            r=json.loads(line); fn=r.get("function"); ins=r.get("instruction","")
            if not fn: continue
            if "rip" in ins:
                m=RIP.search(ins)
                if m:
                    try: tgt=int(r["pc"],16)+r.get("size",0)+int(m.group(1),16)
                    except (ValueError,KeyError): tgt=None
                    if tgt is not None:
                        s=resolve(data,secs,tgt)
                        if s: strs[fn].append(s)
            if ins.startswith("mov"):
                mi=IMM.search(ins)
                if mi:
                    s=imm_string(mi.group(1))
                    if s: strs[fn].append(s)
    feats={}
    for fn,ls in strs.items():
        feats[fn]={
          "s_count":min(len(ls),50),
          "s_path":int(any('/' in x for x in ls)),
          "s_syspath":int(any(PAT_SYS.search(x) for x in ls)),
          "s_shell":int(any(PAT_SH.search(x) for x in ls)),
          "s_cred":int(any(PAT_CR.search(x) for x in ls)),
          "s_cap":int(any(PAT_CAP.search(x) for x in ls)),
          "s_fmt":int(any('%s' in x or '%d' in x for x in ls)),
        }
    return feats

SCOLS=["s_count","s_path","s_syspath","s_shell","s_cred","s_cap","s_fmt"]

def main():
    progs=["cherry_http_4b877df","dnsmasq_2_90","doas_6_8_2","dropbear_2022_83",
           "lighttpd_1_4_59","microhttpserver_4398570","nginx_1_4_0_validation",
           "openssh_9_7p1","polkit_0_105_31","proftpd_1_3_3c","sudo_1_8_31",
           "thttpd_2_29","vsftpd_3_0_5","wu_ftpd_2_6_1"]
    S={}
    for prog in progs:
        S[prog]=strings_for(prog)
        print(f"{prog:24s} functions with strings: {len(S[prog])}")
    for path in (REL/"dataset"/"integrated_function_features.csv", REL/"data"/"all_function_features.csv"):
        rows=list(csv.DictReader(open(path))); fields=list(rows[0].keys())
        changed=0
        for r in rows:
            nv=S.get(r["target_id"],{}).get(r["function"])
            if not nv: continue
            for c in SCOLS:
                old=r.get(c)
                new=str(nv[c])
                if old is not None and str(old).split(".")[0]!=new:
                    r[c]=new; changed+=1
                elif old is not None:
                    r[c]=new
        with open(path,"w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
        print(f"patched {path.name}: {changed} s_* cell changes")

if __name__=="__main__":
    main()
