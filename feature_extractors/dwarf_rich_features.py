#!/usr/bin/env python3
"""Bold DWARF features: use EVERYTHING the debug info gives (no leakage-avoidance).
 - source FILE the function is defined in (auth.c/privs.c/exec.c... = strong type hint)
 - PARAMETER names (valid_user, password, path, cmd, uid...)
 - PARAMETER types (struct passwd*, uid_t, char*, cap_t, mode_t, sockaddr...)
All from the DWARF of the (debug) binary. Program-agnostic keyword flags.
Emits ml_dataset/dwarf_rich_features.json
"""
import json, re, subprocess, sys
from pathlib import Path
from collections import defaultdict, Counter
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG
import bin_effect_features as BE
import bin_string_features as BS

FILE_KW=['auth','priv','pass','login','cred','perm','polic','access','sudoers','exec',
         'session','secure','cap','chan','pty','user','sign','key','referer','sftp','ftpcmd','privop']
PNAME_KW=['passwd','password','pwd','uid','gid','user','cred','pubkey','key','path','file',
          'cmd','command','mode','perm','addr','host','refer','sig','token','principal','auth','name','dir']
PTYPE_KW=['passwd','uid_t','gid_t','cap','mode_t','sockaddr']
LINE=re.compile(r'^(\S+\.\w+)\s+\d+\s+(0x[0-9a-f]+)')

def func2file(prog):
    elf=BS.binpath(prog)
    if not elf: return {}
    txt=subprocess.run(["objdump","--dwarf=decodedline",str(elf)],capture_output=True,text=True).stdout
    addr2file={}
    for ln in txt.splitlines():
        m=LINE.match(ln.strip())
        if m: addr2file[int(m.group(2),16)]=m.group(1).lower()
    # function -> pcs from disassembly
    f2pc=defaultdict(list)
    with BE.disasm_path(prog).open() as f:
        for line in f:
            if '"pc"' not in line: continue
            r=json.loads(line)
            if r.get("function") and r.get("pc"): f2pc[r["function"]].append(int(r["pc"],16))
    out={}
    for fn,pcs in f2pc.items():
        files=[addr2file[p] for p in pcs if p in addr2file]
        if files: out[fn]=Counter(files).most_common(1)[0][0]
    return out

def main():
    out={}
    for prog in CG.SRC:
        dwp=BE.disasm_path(prog)
        if not dwp.exists(): continue
        dwf=BS.binpath(prog)
        dw=json.loads((CG.DWARF[prog]).read_text())["functions"] if CG.DWARF[prog].exists() else {}
        params={}
        for v in dw.values():
            if isinstance(v,dict) and v.get("name"):
                pn=" ".join(p.get("name","") or "" for p in v.get("params",[])).lower()
                pt=" ".join(p.get("type","") or "" for p in v.get("params",[])).lower()
                nstr=sum(1 for p in v.get("params",[]) if p.get("is_pointer") and "char" in str(p.get("type","")).lower())
                params[v["name"]]=(pn,pt,nstr)
        f2f=func2file(prog)
        feats={}
        names=set(params)|set(f2f)
        for fn in names:
            pn,pt,nstr=params.get(fn,("","",0)); fname=f2f.get(fn,"")
            row={f"file_{k}":int(k in fname) for k in FILE_KW}
            row.update({f"pname_{k}":int(k in pn) for k in PNAME_KW})
            row.update({f"ptype_{k}":int(k in pt) for k in PTYPE_KW})
            row["n_str_param"]=int(nstr)
            feats[fn]=row
        out[prog]=feats
        print(f"{prog:24s} funcs with dwarf-rich feats: {len(feats)}  (mapped-to-file: {len(f2f)})")
    (CG.ROOT/"ml_dataset"/"dwarf_rich_features.json").write_text(json.dumps(out))
    print("wrote ml_dataset/dwarf_rich_features.json")

if __name__=="__main__":
    main()
