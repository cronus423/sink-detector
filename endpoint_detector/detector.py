#!/usr/bin/env python3
"""File-read-disclosure ENDPOINT detector — P1 (capability recall) + P2 (same-function
forward taint) + P3 (cross-function via struct buffer). Pure static, no API.
Output: endpoints where file-read content reaches an external output channel.
"""
import json, re, sys
from pathlib import Path
from collections import defaultdict, deque
ROOT=Path("/home/peiyao/program/LLM_AUTO_DOP/dfb_attack_feasibility_rethink/program_targets")
REPO=ROOT.parent
def art(prog):
    base = REPO/"nginx_1_4_0_validation" if prog=="nginx_1_4_0_validation" else ROOT/prog
    return base/"artifacts/stage_02_static_ir_cfg"

SYM=re.compile(r'<([^>+@]+)')
# ---- primitive sets ----
READ_ACCESS=set("open open64 openat openat64 fopen fopen64 freopen read pread pread64 readv "
                "fread fread_unlocked fgets fgets_unlocked getline getdelim mmap mmap64 "
                "opendir readdir scandir".split())     # P1 recall
CONTENT_READ={"fread":"rdi","fread_unlocked":"rdi","fgets":"rdi","fgets_unlocked":"rdi",
              "read":"rsi","pread":"rsi","pread64":"rsi","readv":"rsi","getline":"rdi","getdelim":"rdi"}
OUTPUT={"send":"rsi","sendto":"rsi","write":"rsi","writev":"rsi","pwrite":"rsi","pwrite64":"rsi",
        "fwrite":"rdi","fwrite_unlocked":"rdi","fputs":"rdi","fputs_unlocked":"rdi","puts":"rdi",
        "printf":"rsi","__printf_chk":"rdx","fprintf":"rdx","vfprintf":"rdx"}
NET_OUTPUT={"send","sendto","sendmsg","sendfile","sendfile64","writev"}   # clean external
STDOUT_OUTPUT={"puts","printf","__printf_chk","putchar","putchar_unlocked"}  # implicit stdout -> external
# P5: fd/stream arg register per output prim (to classify the channel). NET/STDOUT need no arg.
CHAN_ARG={"write":"rdi","pwrite":"rdi","pwrite64":"rdi","fwrite":"rcx","fwrite_unlocked":"rcx",
          "fputs":"rsi","fputs_unlocked":"rsi","fprintf":"rdi","vfprintf":"rdi","putc":"rsi","fputc":"rsi"}
OPEN_FAMILY={"open","open64","openat","openat64","fopen","fopen64","freopen","creat","creat64"}
# P2 char loop: getc-family return (eax) -> putc-family char arg (edi/rdi)
GETC={"getc","fgetc","getc_unlocked","fgetc_unlocked","getchar","getchar_unlocked","getw"}
PUTC={"putc":"rsi","fputc":"rsi","putc_unlocked":"rsi","fputc_unlocked":"rsi",
      "putchar":None,"putchar_unlocked":None,"putw":"rsi"}   # char arg = rdi; stream (for channel) as noted
COPY={"memcpy":("rdi","rsi"),"memmove":("rdi","rsi"),"strcpy":("rdi","rsi"),"strncpy":("rdi","rsi"),
      "strlcpy":("rdi","rsi"),"stpcpy":("rdi","rsi"),"strcat":("rdi","rsi"),"strncat":("rdi","rsi")}
CALLER_SAVED={"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"}
ALIAS={"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi","ebp":"rbp","esp":"rsp",
       "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13","r14d":"r14","r15d":"r15"}
def nrm(r): return ALIAS.get(r,r)
SPELL={}
for _k,_v in ALIAS.items(): SPELL.setdefault(_v,[_v]).append(_k)
def rx(reg): return "(?:"+"|".join(SPELL.get(reg,[reg]))+")"   # regex alt of a reg's 64/32-bit spellings
SLOT=re.compile(r'\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\]')

def load(prog):
    d=art(prog); dis=d/"nginx_disassembly.jsonl"
    if not dis.exists(): return None,None
    funcs=defaultdict(list)
    for l in dis.open():
        r=json.loads(l); fn=r.get("function")
        if fn and fn not in(".plt",".plt.sec"): funcs[fn].append(r.get("instruction",""))
    dwf=d/"dwarf_facts.json"
    structs=json.load(dwf.open()).get("structs",{}) if dwf.exists() else {}
    return funcs, structs

# ---------- P1: capability recall (bounded reach to a file-access primitive) ----------
def recall_B(funcs, K=3):
    callees=defaultdict(set); direct=set(); allf=set(funcs)
    for fn,insns in funcs.items():
        for ins in insns:
            if not ins.startswith("call"): continue
            m=SYM.search(ins)
            if not m: continue
            t=m.group(1).strip()
            if t in READ_ACCESS: direct.add(fn)
            else: callees[fn].add(t)
    for fn in list(callees): callees[fn]&=allf
    rev=defaultdict(set)
    for fn,cs in callees.items():
        for c in cs: rev[c].add(fn)
    dist={fn:0 for fn in direct}; dq=deque(direct)
    while dq:
        u=dq.popleft()
        for p in rev.get(u,()):
            if p not in dist and dist[u]+1<=K: dist[p]=dist[u]+1; dq.append(p)
    return set(dist)

# ---------- P5: output-channel discrimination (external egress vs self-opened file / stderr) ----------
def slot_from_open(insns, from_idx, slot):
    """Was `slot` most recently written from an open-family return (self-opened file)?"""
    pat=r'mov (?:QWORD PTR |DWORD PTR )?\['+re.escape(slot)+r'\],(?:[re][a-z0-9]{1,3})$'
    for k in range(from_idx-1, max(-1, from_idx-250), -1):
        if re.match(pat, insns[k]):
            for j in range(k-1, max(-1,k-8), -1):           # what call produced the stored value?
                if insns[j].startswith('call'):
                    mm=SYM.search(insns[j])
                    return bool(mm and mm.group(1).strip() in OPEN_FAMILY)
            return False
    return False
FD_PRIMS={"write","pwrite","pwrite64"}    # raw-fd output (arg is an int fd, not a FILE*)
def channel_of(insns, idx, reg, is_fd=False, depth=0):
    """Classify the output fd/stream held in `reg` at call site `idx`: 'ext' or 'local'.
    is_fd=True: raw int fd (write) — a rip-relative global fd is a program-managed FILE (local),
      since the client socket fd is per-connection (stack/struct), and stdout is fd literal 1.
    is_fd=False: FILE* stream (fwrite/fputs/..) — a rip-relative global is stdout/stderr => ext.
    self-open()ed fd/stream or stderr(fd 2) -> local. Unknown defaults to ext (drop only confident locals)."""
    if reg is None: return "ext"
    if depth>4: return "ext"
    reg=nrm(reg); R=rx(reg)
    for k in range(idx-1, max(-1, idx-40), -1):
        ins=insns[k]
        if re.match(rf'mov {R},(?:QWORD PTR |DWORD PTR )?\[rip[+-]0x[0-9a-fA-F]+\]', ins):
            return "local" if is_fd else "ext"               # global int fd=own file; global FILE*=stdout
        m=re.match(rf'mov {R},(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\]', ins)
        if m:
            slot=m.group(1)+m.group(2)
            return "local" if slot_from_open(insns,k,slot) else "ext"
        m=re.match(rf'mov {R},([re][a-z0-9]{{1,3}})$', ins)
        if m: return channel_of(insns,k,nrm(m.group(1)),is_fd,depth+1)
        m=re.match(rf'mov {R},(0x[0-9a-fA-F]+)$', ins)
        if m: return "local" if int(m.group(1),16)==2 else "ext"   # fd 2 = stderr
        if re.match(rf'\w+\s+{R}\b', ins) and not ins.startswith(('cmp','test')):
            return "ext"                                     # reg produced by some other op -> unknown -> ext
    return "ext"
def out_is_external(insns, idx, prim):
    if prim in NET_OUTPUT or prim in STDOUT_OUTPUT: return True
    return channel_of(insns, idx, CHAN_ARG.get(prim), is_fd=prim in FD_PRIMS) == "ext"

# ---------- P2b: getc/putc character-copy loop (file char -> external stream) ----------
def p2_charloop(insns):
    """getc/fgetc return (eax) flows to putc/fputc/putchar char arg (edi), output external.
    Two-pass to handle loop layout where putc textually precedes getc."""
    val=set()   # regs currently holding a getc-derived char
    hit=[]
    for _ in range(2):
        for i,ins in enumerate(insns):
            if ins.startswith("call"):
                m=SYM.search(ins); t=m.group(1).strip() if m else ""
                if t in PUTC and "rdi" in val:
                    if t in ("putchar","putchar_unlocked") or channel_of(insns,i,PUTC[t])=="ext":
                        hit.append(t)
                if t in GETC:
                    for r in CALLER_SAVED: val.discard(r)
                    val.add("rax"); continue
                for r in CALLER_SAVED: val.discard(r)     # callee-saved (rbx/r12..) survive -> loop var
                continue
            m=re.match(r'mov(?:zx|sx)?\s+([re][a-z0-9]{1,3}),([re][a-z0-9]{1,3})$', ins)
            if m:
                s=nrm(m.group(2)); d=nrm(m.group(1))
                if s in val: val.add(d)
                else: val.discard(d)
                continue
            m=re.match(r'\w+\s+([re][a-z0-9]{1,3})\b', ins)   # any other write to a reg clears it
            if m and not ins.startswith(('cmp','test','push')): val.discard(nrm(m.group(1)))
    return sorted(set(hit))

# ---------- P2: same-function forward taint (stack-slot taint w/ copy propagation) ----------
def p2_samefunc(insns):
    # order-INDEPENDENT: collect read-dest slots, output-src slots, copy edges;
    # then copy-propagate to fixpoint and intersect (handles read-in-loop-condition,
    # output-in-loop-body where output textually precedes the read).
    regslot={}; read_slots=set(); output_uses=set(); copy_edges=[]; out_prims=set()
    def dest_reg(ins):
        m=re.match(r'\w+\s+(r[a-z0-9]+|e[a-z]x|e[bsd]i|e[bs]p)\b',ins)
        return nrm(m.group(1)) if m else None
    for i,ins in enumerate(insns):
        if ins.startswith("call"):
            m=SYM.search(ins); t=m.group(1).strip() if m else ""
            if t in OUTPUT and OUTPUT[t] in regslot and out_is_external(insns,i,t):  # P5: external channel only
                output_uses.add(regslot[OUTPUT[t]]); out_prims.add(t)
            if t in CONTENT_READ and CONTENT_READ[t] in regslot: read_slots.add(regslot[CONTENT_READ[t]])
            if t in COPY:
                dr,sr=COPY[t]
                if dr in regslot and sr in regslot: copy_edges.append((regslot[dr],regslot[sr]))
            for r in CALLER_SAVED: regslot.pop(r,None)
            continue
        m=re.match(r'lea\s+(r[a-z0-9]+),\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\]',ins)
        if m: regslot[nrm(m.group(1))]=m.group(2)+m.group(3); continue
        m2=re.match(r'mov\s+(r[a-z0-9]+),(r[a-z0-9]+)$',ins)
        if m2:
            s=nrm(m2.group(2))
            if s in regslot: regslot[nrm(m2.group(1))]=regslot[s]
            else: regslot.pop(nrm(m2.group(1)),None)
            continue
        dr=dest_reg(ins)
        if dr: regslot.pop(dr,None)
    tainted=set(read_slots); ch=True
    while ch:
        ch=False
        for dst,src in copy_edges:
            if src in tainted and dst not in tainted: tainted.add(dst); ch=True
    hit=tainted & output_uses
    return [(sorted(out_prims), sorted(hit))] if hit else []

# ---------- P3: cross-function via struct buffer (reuse sendbuf approach) ----------
MEM=re.compile(r'\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\]')
def reg_load_off(insns,idx,reg,depth=0):
    if depth>4: return None
    for k in range(idx-1,max(-1,idx-30),-1):
        ins=insns[k]
        m=re.match(rf'mov {reg},(?:QWORD PTR )?\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\]',ins)
        if m: return int(m.group(2),16) if m.group(2)[0]=='+' else -int(m.group(2)[1:],16)
        m2=re.match(rf'lea {reg},\[(r[a-z0-9]+)',ins)
        if m2: return reg_load_off(insns,k,m2.group(1),depth+1)
        m3=re.match(rf'mov {reg},(r[a-z0-9]+)$',ins)
        if m3: return reg_load_off(insns,k,m3.group(1),depth+1)
    return None
def walk_struct(structs,sname,off):
    v=structs.get(sname)
    if not v: return None
    for m in v.get("members",[]):
        mo=m.get("offset",0); sz=m.get("byte_size",0) or 1
        if mo<=off<mo+sz:
            if m.get("is_pointer") and off==mo: return (sname,m.get("name"),mo)
            pt=m.get("pointee") or m.get("type")
            if pt in structs and not m.get("is_pointer"):
                s=walk_struct(structs,pt,off-mo)
                if s: return s
    return None
def p3_crossfunc(funcs,structs):
    if not structs: return {}
    send_offs=set()
    for fn,insns in funcs.items():
        for i,ins in enumerate(insns):
            if not ins.startswith("call"): continue
            m=SYM.search(ins)
            if not m or m.group(1).strip() not in ("send","sendto"): continue
            off=reg_load_off(insns,i,"rsi")
            if off and off>0: send_offs.add(off)
    targets=set()
    for off in send_offs:
        for sname in structs:
            d=walk_struct(structs,sname,off)
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
    out={}
    for fn,insns in funcs.items():
        for i,ins in enumerate(insns):
            mm=MEM.search(ins)
            if not mm: continue
            off=int(mm.group(2),16) if mm.group(2)[0]=='+' else -int(mm.group(2)[1:],16)
            if off not in reach: continue
            for k in range(i,min(len(insns),i+25)):
                if insns[k].startswith("call"):
                    sc=SYM.search(insns[k])
                    if sc and sc.group(1).strip() in CONTENT_READ:   # require a real file READ (not memcpy of a constant)
                        out[fn]=out.get(fn,0)+1; break
    return out

def run(prog):
    funcs,structs=load(prog)
    if funcs is None: return None
    B=recall_B(funcs)
    endpoints={}
    for fn in funcs:
        h2=p2_samefunc(funcs[fn])
        if h2: endpoints[fn]=("samefunc",h2)
        # NOTE: p2_charloop (getc/putc) is intentionally NOT wired: within one function it
        # cannot tell download (file->socket, disclosure) from upload (socket->file, a
        # file_mutation sink, out of scope) — both streams are passed-in FILE*s, so direction
        # needs cross-function (P4) resolution. Wiring it flags wu_ftpd receive_data (upload FP)
        # and still misses send_data (loop-carried ebx reuse). Revisit when P4 lands.
    for fn,c in p3_crossfunc(funcs,structs).items():
        if fn not in endpoints: endpoints[fn]=("crossbuf",c)
    return B, endpoints

GT={"cherry_http_4b877df":["serve_static"],"microhttpserver_4398570":["_ReadStaticFiles"],
"thttpd_2_29":["mmc_map","ls"],"lighttpd_1_4_59":["http_response_send_file"],
"nginx_1_4_0_validation":["ngx_open_and_stat_file"],"vsftpd_3_0_5":["handle_retr"],
"proftpd_1_3_3c":["xfer_retr"],"wu_ftpd_2_6_1":["retrieve"],"dnsmasq_2_90":["check_tftp_fileperm"],
"openssh_9_7p1":["process_open","process_read"],"tinyhttpd_jdb":["serve_file"],
"gophernicus_3_1":["send_text_file","send_binary_file"]}

if __name__=="__main__":
    progs=sys.argv[1:] or list(GT)
    for p in progs:
        r=run(p)
        if r is None: print(f"{p}: no artifacts"); continue
        B,ep=r
        gt=GT.get(p,[])
        cov=[f"{g}:{'✓'+ep[g][0] if g in ep else '✗'}" for g in gt]
        print(f"\n### {p}  |B|={len(B)}  endpoints={len(ep)}")
        print("   GT read-sinks:", " ".join(cov))
        # show a few endpoints (non-GT) as FP indication
        others=[f for f in ep if f not in gt][:8]
        print("   other endpoints:", ", ".join(f"{f}({ep[f][0]})" for f in others))
