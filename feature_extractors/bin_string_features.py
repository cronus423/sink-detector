#!/usr/bin/env python3
"""Binary-derived string/constant features (replaces the dropped source ones).

For each function, resolve the .rodata strings it references via rip-relative
operands in the disassembly (target = pc + insn_size + disp), read the
null-terminated string straight from the ELF. 100% binary; no source.

Emits ml_dataset/bin_string_features.json { program: { func: {s_*} } }
"""
import json, re, subprocess, sys
from pathlib import Path
from collections import defaultdict
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG
import bin_effect_features as BE

REPO = CG.ROOT.parent
def binpath(prog):
    if prog == "nginx_1_4_0_validation":
        d = REPO/"nginx_1_4_0_validation/target"
    else:
        d = CG.ROOT/prog/"target"
    if not d.exists(): return None
    elfs=[]
    for p in d.rglob("*"):
        if p.is_file() and (p.stat().st_mode & 0o111) and p.suffix not in (".sh",".so",".md",".json"):
            try:
                if p.read_bytes()[:4]==b"\x7fELF": elfs.append(p)
            except: pass
    return max(elfs, key=lambda p:p.stat().st_size) if elfs else None

RIP = re.compile(r'\[rip([+-]0x[0-9a-fA-F]+)\]')
# small servers stack-initialize path/format strings via immediate movs
# (e.g. `movabs rax,0x2f636974617473` = "static/"), which have NO rodata
# reference and were invisible to rip-relative extraction. Reconstruct them.
IMM = re.compile(r',\s*(0x[0-9a-fA-F]{7,16})\b')
def imm_string(h):
    v = int(h, 16); nb = (len(h) - 2 + 1) // 2
    try: b = v.to_bytes(nb, "little")
    except OverflowError: return None
    b = b.split(b"\x00", 1)[0]                       # stop at NUL
    if len(b) >= 3 and all(32 <= c < 127 for c in b):
        return b.decode("ascii")
    return None
PAT_SYS = re.compile(r'^/(etc|var|tmp|usr|bin|sbin|dev|proc|lib|root)\b|^/[a-z]+/')
PAT_SH  = re.compile(r'/bin/sh|/bin/bash|(^|/)(sh|bash|dash)$')
PAT_CR  = re.compile(r'uid|gid|user|passwd|shadow|root|group|privile|cred|login|setuid', re.I)
PAT_CAP = re.compile(r'cap_|chroot|capab|keepcap', re.I)

def load_sections(elf):
    out=[]
    txt=subprocess.run(["objdump","-h",str(elf)],capture_output=True,text=True).stdout
    for line in txt.splitlines():
        p=line.split()
        if len(p)>=7 and p[0].isdigit():
            name,size,vma,lma,off=p[1],int(p[2],16),int(p[3],16),int(p[4],16),int(p[5],16)
            out.append((name,vma,size,off))
    return out

def resolve(data, sections, vaddr):
    for name,vma,size,off in sections:
        if vma<=vaddr<vma+size and name.startswith((".rodata",".data.rel.ro")):
            fo=off+(vaddr-vma)
            end=data.find(b"\x00",fo,fo+200)
            if end<0: return None
            s=data[fo:end]
            try: s=s.decode("ascii")
            except: return None
            return s if len(s)>=3 and all(32<=ord(c)<127 for c in s) else None
    return None

def main():
    out={}; tokens={}
    for prog in CG.SRC:
        elf=binpath(prog); dpath=BE.disasm_path(prog)
        if not elf or not dpath.exists():
            print(f"{prog:24s} NO BIN"); continue
        data=elf.read_bytes(); secs=load_sections(elf)
        strs=defaultdict(list)
        with dpath.open() as f:
            for line in f:
                r=json.loads(line); fn=r.get("function"); ins=r.get("instruction","")
                if not fn: continue
                if "rip" in ins:
                    m=RIP.search(ins)
                    if m:
                        try: disp=int(m.group(1),16); tgt=int(r["pc"],16)+r.get("size",0)+disp
                        except: tgt=None
                        if tgt is not None:
                            s=resolve(data,secs,tgt)
                            if s: strs[fn].append(s)
                if ins.startswith("mov"):                 # stack-immediate strings
                    mi=IMM.search(ins)
                    if mi:
                        s=imm_string(mi.group(1))
                        if s: strs[fn].append(s)
        dw=CG.dwarf_names(CG.DWARF[prog])
        feats={}
        for fn,ls in strs.items():
            if dw and fn not in dw: continue
            feats[fn]={
              "s_count":min(len(ls),50),
              "s_path":int(any('/' in x for x in ls)),
              "s_syspath":int(any(PAT_SYS.search(x) for x in ls)),
              "s_shell":int(any(PAT_SH.search(x) for x in ls)),
              "s_cred":int(any(PAT_CR.search(x) for x in ls)),
              "s_cap":int(any(PAT_CAP.search(x) for x in ls)),
              "s_fmt":int(any('%s' in x or '%d' in x for x in ls)),
            }
        out[prog]=feats
        # rich token doc per function = all referenced rodata strings, lowercased words
        for fn,ls in strs.items():
            if dw and fn not in dw: continue
            toks=re.findall(r'[A-Za-z_]{3,}', " ".join(ls).lower())
            if toks: tokens.setdefault(prog,{})[fn]=" ".join(toks[:200])
        print(f"{prog:24s} functions with rodata strings: {len(feats)}  (bin={elf.name})")
    (CG.ROOT/"ml_dataset"/"bin_string_features.json").write_text(json.dumps(out))
    (CG.ROOT/"ml_dataset"/"bin_string_tokens.json").write_text(json.dumps(tokens))
    print("wrote bin_string_features.json + bin_string_tokens.json")

if __name__=="__main__":
    main()
