#!/usr/bin/env python3
"""Compute writes_send_buffer per function for ALL programs; check coverage on the
labeled file-read sinks. Send-buffer = a struct field whose contents feed send()/sendto();
identified via DWARF struct decomposition; feature = function writes to that field's offset(s).
"""
import json, re
from pathlib import Path
from collections import defaultdict
ROOT=Path("/home/peiyao/program/LLM_AUTO_DOP/dfb_attack_feasibility_rethink/program_targets")
REPO=ROOT.parent
def art(prog):
    base = REPO/"nginx_1_4_0_validation" if prog=="nginx_1_4_0_validation" else ROOT/prog
    return base/"artifacts/stage_02_static_ir_cfg"

SYM=re.compile(r'<([^>+@]+)')
MEM=re.compile(r'\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\]')
SENDBUF_CALLS={"send","sendto"}                    # buffer arg = rsi
WRITE_CALLS={"memcpy","memmove","memset","fread","fread_unlocked","fgets","fgets_unlocked",
             "sprintf","__sprintf_chk","snprintf","__snprintf_chk","strcpy","strcat","stpcpy","read"}

def load(prog):
    d=art(prog)
    dis=d/"nginx_disassembly.jsonl"; dwf=d/"dwarf_facts.json"
    if not dis.exists() or not dwf.exists(): return None,None
    funcs=defaultdict(list)
    for l in open(dis):
        r=json.loads(l); fn=r.get("function")
        if fn and fn not in(".plt",".plt.sec"): funcs[fn].append(r)
    structs=json.load(open(dwf)).get("structs",{})
    return funcs, structs

def reg_load_off(insns,idx,reg,depth=0):
    if depth>4: return None
    for k in range(idx-1,max(-1,idx-30),-1):
        ins=insns[k]["instruction"]
        m=re.match(rf'mov {reg},(?:QWORD PTR )?\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\]',ins)
        if m: return int(m.group(2),16) if m.group(2)[0]=='+' else -int(m.group(2)[1:],16)
        m2=re.match(rf'lea {reg},\[(r[a-z0-9]+)',ins)
        if m2: return reg_load_off(insns,k,m2.group(1),depth+1)
        m3=re.match(rf'mov {reg},(r[a-z0-9]+)$',ins)
        if m3: return reg_load_off(insns,k,m3.group(1),depth+1)
    return None

def walk(structs,sname,off):
    v=structs.get(sname)
    if not v: return None
    for m in v.get("members",[]):
        mo=m.get("offset",0); sz=m.get("byte_size",0) or 1
        if mo<=off<mo+sz:
            if m.get("is_pointer") and off==mo: return (sname,m.get("name"),mo)
            pt=m.get("pointee") or m.get("type")
            if pt in structs and not m.get("is_pointer"):
                s=walk(structs,pt,off-mo)
                if s: return s
    return None

def reaching_offsets(structs, send_offsets):
    targets=set()
    for off in send_offsets:
        for sname in structs:
            d=walk(structs,sname,off)
            if d: targets.add((d[0],d[1])); break
    reach=set()
    for tname,fld in targets:
        lo=next((m["offset"] for m in structs[tname].get("members",[]) if m.get("name")==fld),None)
        if lo is None: continue
        reach.add(lo)
        for sname,v in structs.items():
            for m in v.get("members",[]):
                if (m.get("pointee")==tname or m.get("type")==tname) and not m.get("is_pointer"):
                    reach.add(m.get("offset")+lo)
    return reach, targets

def compute(prog):
    funcs,structs=load(prog)
    if funcs is None: return {}, set(), set()
    # 1. send-buffer offsets from send/sendto sites
    send_offsets=set()
    for fn,insns in funcs.items():
        for i,r in enumerate(insns):
            ins=r["instruction"]
            if not ins.startswith("call"): continue
            s=SYM.search(ins)
            if not s or s.group(1).strip() not in SENDBUF_CALLS: continue
            off=reg_load_off(insns,i,"rsi")
            if off is not None and off>0: send_offsets.add(off)
    reach,targets=reaching_offsets(structs,send_offsets)
    # 2. writes_send_buffer per function
    out={}
    for fn,insns in funcs.items():
        hits=0
        for i,r in enumerate(insns):
            m=MEM.search(r["instruction"])
            if not m: continue
            off=int(m.group(2),16) if m.group(2)[0]=='+' else -int(m.group(2)[1:],16)
            if off not in reach: continue
            for k in range(i,min(len(insns),i+25)):
                ik=insns[k]["instruction"]
                if ik.startswith("call"):
                    sc=SYM.search(ik)
                    if sc and sc.group(1).strip() in WRITE_CALLS: hits+=1; break
        if hits: out[fn]=hits
    return out, reach, targets

PROGS=["cherry_http_4b877df","dnsmasq_2_90","dropbear_2022_83","lighttpd_1_4_59",
"microhttpserver_4398570","nginx_1_4_0_validation","openssh_9_7p1","proftpd_1_3_3c",
"sudo_1_8_31","thttpd_2_29","vsftpd_3_0_5","wu_ftpd_2_6_1","tinyhttpd_jdb","gophernicus_3_1"]
READ_SINKS={"cherry_http_4b877df":["serve_static"],"microhttpserver_4398570":["_ReadStaticFiles"],
"thttpd_2_29":["mmc_map","ls"],"lighttpd_1_4_59":["http_response_send_file"],
"nginx_1_4_0_validation":["ngx_open_and_stat_file"],"vsftpd_3_0_5":["handle_retr"],
"proftpd_1_3_3c":["xfer_retr"],"wu_ftpd_2_6_1":["retrieve"],"dnsmasq_2_90":["check_tftp_fileperm"],
"openssh_9_7p1":["process_open","process_read"],"tinyhttpd_jdb":["serve_file"],
"gophernicus_3_1":["send_text_file","send_binary_file"]}

ALL={}
print(f"{'program':22s} {'#send-buf structs':>17s} {'#funcs writing sb':>18s}   read-sink coverage")
for p in PROGS:
    out,reach,targets=compute(p)
    for fn,v in out.items(): ALL[(p,fn)]=v
    tags=[f"{s}={out.get(s,0)}" for s in READ_SINKS.get(p,[])]
    tnames=",".join(sorted({t[1] for t in targets})) or "-"
    print(f"{p:22s} {len(targets):>17} {len(out):>18}   {' '.join(tags)}   [{tnames}]")
json.dump({f"{k[0]}||{k[1]}":v for k,v in ALL.items()},
          open("/tmp/claude-1000/-home-peiyao-program-LLM-AUTO-DOP-sink-detector/4bb7eb76-d71a-4f30-a2ba-06ac7a459a30/scratchpad/writes_send_buffer.json","w"))
print("\nsaved writes_send_buffer.json")
