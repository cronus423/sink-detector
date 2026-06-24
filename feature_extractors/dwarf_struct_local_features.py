#!/usr/bin/env python3
"""Additive DWARF features: per function, LOCAL VARIABLE names + referenced
STRUCT/typedef type names (pyelftools over the binary's .debug_info). 100% binary.
Struct types (passwd/sockaddr/stat/cap...) are libc-universal -> generalize and
are independent of the function name (reduces name-label circularity).
Emits ml_dataset/dwarf_struct_local_features.json
"""
import json, sys
from pathlib import Path
from collections import defaultdict
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG
import bin_string_features as BS
from elftools.elf.elffile import ELFFile

LOCAL_KW=['password','passwd','pwd','crypt','salt','hash','shadow','uid','gid','cred','key',
          'pubkey','sig','token','principal','path','file','cmd','command','perm','mode','addr',
          'host','refer','user','group','cap','secret','nonce','cookie','ticket','session','priv']
TYPE_KW=['passwd','group','spwd','sockaddr','stat','cap_','in_addr','termios','ucred','rlimit','pam']

def resolve_type(die, depth=0):
    if depth>10 or die is None: return None
    if die.tag in ('DW_TAG_structure_type','DW_TAG_union_type','DW_TAG_typedef','DW_TAG_base_type','DW_TAG_enumeration_type'):
        n=die.attributes.get('DW_AT_name')
        if n:
            try: return n.value.decode(errors='ignore')
            except: return None
    t=die.attributes.get('DW_AT_type')
    if t is None: return None
    try: nxt=die.cu.get_DIE_from_refaddr(t.value + die.cu.cu_offset)
    except Exception:
        try: nxt=die.cu.get_DIE_from_refaddr(t.value)
        except Exception: return None
    return resolve_type(nxt, depth+1)

def main():
    out={}
    for prog in CG.SRC:
        elf=BS.binpath(prog)
        if not elf: continue
        feats=defaultdict(lambda: {"locals":set(),"types":set()})
        try:
            with open(elf,'rb') as fh:
                e=ELFFile(fh)
                if not e.has_dwarf_info(): continue
                dw=e.get_dwarf_info()
                for cu in dw.iter_CUs():
                    for die in cu.iter_DIEs():
                        if die.tag!='DW_TAG_subprogram': continue
                        nm=die.attributes.get('DW_AT_name')
                        if not nm: continue
                        try: fn=nm.value.decode(errors='ignore')
                        except: continue
                        for ch in die.iter_children():
                            if ch.tag in ('DW_TAG_variable','DW_TAG_formal_parameter'):
                                vn=ch.attributes.get('DW_AT_name')
                                if vn:
                                    try: feats[fn]["locals"].add(vn.value.decode(errors='ignore').lower())
                                    except: pass
                                tn=resolve_type(ch)
                                if tn: feats[fn]["types"].add(tn.lower())
        except Exception as ex:
            print(f"{prog:24s} ERR {ex}"); continue
        dwn=CG.dwarf_names(CG.DWARF[prog])
        out[prog]={}
        for fn,d in feats.items():
            if dwn and fn not in dwn: continue
            lv=" ".join(d["locals"]); ty=" ".join(d["types"])
            row={f"lv_{k}":int(k in lv) for k in LOCAL_KW}
            row.update({f"ty_{k}":int(k in ty) for k in TYPE_KW})
            out[prog][fn]=row
        print(f"{prog:24s} funcs with local/struct feats: {len(out[prog])}")
    (CG.ROOT/"ml_dataset"/"dwarf_struct_local_features.json").write_text(json.dumps(out))
    print("wrote ml_dataset/dwarf_struct_local_features.json")

if __name__=="__main__":
    main()
