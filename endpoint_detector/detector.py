#!/usr/bin/env python3
"""File-read-disclosure ENDPOINT detector — P1 (capability recall) + P2 (same-function
forward taint) + P3 (cross-function via struct buffer) + P4 (cross-function fd delegation:
open-fd -> read+external-write helper, via arg-passing or a global handle table). Pure
static, no API. Output: endpoints where file-read content reaches an external output channel.
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

# ---------- P4: cross-function fd delegation (open-fd -> read+external-write helper) ----------
# The FTP/SFTP download idiom splits open, read and socket-write across functions and hides
# the raw syscalls behind thin wrappers (vsf_sysutil_read, ftp_write_data, pr_fsio_open,
# handle_to_fd...). P2/P3 (single-function taint / send-buffer) miss it. P4 tracks the fd VALUE
# returned by an open-family primitive across a call boundary until it reaches a helper that
# reads it and egresses externally. Two carriers are implemented:
#   P4a arg-passing : open-fd passed as a register arg into a transfer helper (reads+ext-writes).
#   P4b handle-table: open-fd stored into a global table by a registrar (e.g. sftp handle_new)
#                     and re-read by a consumer via a resolver (handle_to_fd) -> read + ext-write.
# Precision lever = the fd VALUE flow (an open()ed fd reused as a read fd is rare & meaningful),
# NOT call-graph reach (which conflates "reaches open somewhere & read somewhere" -> main()).
# A disclosure origin must be opened READ-only (O_RDONLY); write/create opens (uploads) are
# excluded at the source. See README "P4" + "Known limitations" for the two out-of-reach cases
# (proftpd xfer_retr: open+read behind `call <reg>` vtables; lighttpd http_response_send_file:
# egress is a decoupled sendfile in the fdevent loop, no read->write taint exists to follow).
P4_READ=set("read pread pread64 readv recv fread fread_unlocked fgets fgets_unlocked getline "
            "getdelim getc fgetc getc_unlocked fgetc_unlocked".split())
P4_EXTWRITE=set("send sendto sendmsg sendfile sendfile64 write writev pwrite pwrite64".split())
P4_ARGREGS=["rdi","rsi","rdx","rcx","r8","r9"]
P4_CALLER_SAVED={"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"}
O_CREAT=0x40; O_WRONLY=1; O_RDWR=2; O_TRUNC=0x200; O_APPEND=0x400
P4_DEST=re.compile(r'^\w+\s+(r[a-z0-9]+|e[a-z][a-z])\b')
def _p4_callee(ins):
    if ins.startswith("call"):
        m=SYM.search(ins)
        if m: return m.group(1).strip()
    return None
def _p4_callees(funcs):
    cg={fn:set() for fn in funcs}
    for fn,insns in funcs.items():
        for ins in insns:
            c=_p4_callee(ins)
            if c: cg[fn].add(c)
    return cg
def _p4_reach(funcs, cg, prims, K):
    """functions transitively reaching (<=K internal hops) a call to any prim in `prims`."""
    allf=set(funcs); direct={fn for fn in funcs if cg[fn]&prims}
    rev=defaultdict(set)
    for fn,cs in cg.items():
        for c in cs&allf: rev[c].add(fn)
    dist={fn:0 for fn in direct}; dq=deque(direct)
    while dq:
        u=dq.popleft()
        for p in rev.get(u,()):
            if p not in dist and dist[u]+1<=K: dist[p]=dist[u]+1; dq.append(p)
    return set(dist)
def _p4_open_wrappers(funcs, cg, maxlen=60):
    """thin (<=maxlen insn) functions that transitively open a file via direct calls."""
    OW=set(); changed=True
    while changed:
        changed=False
        for fn,insns in funcs.items():
            if fn in OW or len(insns)>maxlen: continue
            if cg[fn]&(OPEN_FAMILY|OW): OW.add(fn); changed=True
    return OW
def _p4_const(insns, idx, reg):
    for k in range(idx-1, max(-1, idx-12), -1):
        m=re.match(rf'mov {reg},(0x[0-9a-fA-F]+)$', insns[k])
        if m: return int(m.group(1),16)
        if re.match(rf'\w+\s+{reg}\b', insns[k]) and not insns[k].startswith(('cmp','test')): return None
    return None
def _p4_raw_open_dir(insns, idx, prim):
    """'read' or 'write' for a raw open-family call site (disclosure origins must be read-only)."""
    if prim in ("creat","creat64"): return "write"
    if prim in ("fopen","fopen64","freopen","fdopen"): return "read"   # mode string absent from disasm
    freg="edx" if prim in ("openat","openat64") else "esi"
    mreg="ecx" if prim in ("openat","openat64") else "edx"
    fl=_p4_const(insns, idx, freg)
    if fl is not None:
        return "write" if fl&(O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND) else "read"
    md=_p4_const(insns, idx, mreg)                                     # runtime flags: mode arg => O_CREAT
    return "write" if (md is not None and 0<md<=0o777) else "read"
def _p4_read_open_wrappers(funcs, cg, OW):
    memo={}
    def d(fn, seen):
        if fn in memo: return memo[fn]
        if fn in seen: return "read"
        seen=seen|{fn}; insns=funcs.get(fn,[]); sawread=False
        for i,ins in enumerate(insns):
            c=_p4_callee(ins)
            if c in OPEN_FAMILY:
                if _p4_raw_open_dir(insns,i,c)=="read": sawread=True
            elif c in OW and d(c,seen)=="read": sawread=True
        memo[fn]="read" if sawread else "write"; return memo[fn]
    return {w for w in OW if d(w,set())=="read"}
def _p4_argpass(insns, read_ow, TH):
    """P4a: monotonic (branch/loop-safe) fd taint from a READ-open origin into a TH call arg."""
    fd_slots=set(); hits=set()
    for _ in range(2):
        fd=set()
        for idx,ins in enumerate(insns):
            c=_p4_callee(ins)
            if c is not None:
                if c in TH and (fd&set(P4_ARGREGS)): hits.add(c)
                fd-=P4_CALLER_SAVED
                if c in read_ow: fd.add("rax")
                elif c in OPEN_FAMILY and _p4_raw_open_dir(insns,idx,c)=="read": fd.add("rax")
                continue
            m=re.match(r'mov\s+(r[a-z0-9]+|e[a-z][a-z]),(r[a-z0-9]+|e[a-z][a-z])$',ins)
            if m:
                s=nrm(m.group(2)); dd=nrm(m.group(1))
                fd.add(dd) if s in fd else fd.discard(dd); continue
            m=re.match(r'mov\s+(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\],(r[a-z0-9]+|e[a-z][a-z])$',ins)
            if m:
                if nrm(m.group(3)) in fd: fd_slots.add(m.group(1)+m.group(2))   # monotonic
                continue
            m=re.match(r'mov\s+(r[a-z0-9]+|e[a-z][a-z]),(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\]$',ins)
            if m:
                dd=nrm(m.group(1)); slot=m.group(2)+m.group(3)
                fd.add(dd) if slot in fd_slots else fd.discard(dd); continue
            m=P4_DEST.match(ins)
            if m and not ins.startswith(('cmp','test','push')): fd.discard(nrm(m.group(1)))
    return hits
# --- P4b handle-table: needs instruction addresses to match a global across two functions ---
def _p4_load_recs(prog):
    d=art(prog); dis=d/"nginx_disassembly.jsonl"
    if not dis.exists(): return {}
    recs=defaultdict(list)
    for l in dis.open():
        r=json.loads(l); fn=r.get("function")
        if fn and fn not in(".plt",".plt.sec"): recs[fn].append(r)
    return recs
def _p4_ripabs(r):
    m=re.search(r'\[rip([+-]0x[0-9a-fA-F]+)\]', r["instruction"])
    if not m: return None
    return int(r["pc"],16)+r["size"]+int(m.group(1),16)
_P4_ARGSLOT=re.compile(r'^mov\s+(?:QWORD PTR |DWORD PTR )?\[(rbp[+-]0x[0-9a-fA-F]+)\],(edi|esi|edx|ecx|r8d|r9d|rdi|rsi|rdx|rcx|r8|r9)$')
_P4_ARGIDX={"rdi":0,"rsi":1,"rdx":2,"rcx":3,"r8":4,"r9":5}
_P4_STORE=re.compile(r'^mov\s+(?:QWORD PTR |DWORD PTR )?\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\],(r[a-z0-9]+|e[a-z][a-z])$')
_P4_LOADF=re.compile(r'^mov\s+(r[a-z0-9]+|e[a-z][a-z]),(?:QWORD PTR |DWORD PTR )?\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\]$')
def _p4_dominant_global(recs):
    c=defaultdict(int)
    for r in recs:
        a=_p4_ripabs(r)
        if a is not None and "QWORD" in r["instruction"] and r["instruction"].split()[0]=="mov": c[a]+=1
    return max(c,key=c.get) if c else None
def _p4_registrars(recs_by_fn):
    """fn -> [(arg_index, global_abs, off)]: stores an int arg into a global-backed table entry."""
    out={}
    for fn,recs in recs_by_fn.items():
        if len(recs)>150: continue
        G=_p4_dominant_global(recs)
        if G is None: continue
        aslots={}
        for r in recs:
            mm=_P4_ARGSLOT.match(r["instruction"])
            if mm and mm.group(1) not in aslots and nrm(mm.group(2)) in _P4_ARGIDX:
                aslots[mm.group(1)]=_P4_ARGIDX[nrm(mm.group(2))]
        live=dict(_P4_ARGIDX); found=[]
        for r in recs:
            ins=r["instruction"]; c=_p4_callee(ins)
            if c is not None:
                for rr in list(live):
                    if rr in P4_CALLER_SAVED: live.pop(rr,None)
                continue
            ms=_P4_STORE.match(ins)
            if ms:
                breg=nrm(ms.group(1)); vreg=nrm(ms.group(3))
                off=int(ms.group(2),16) if ms.group(2)[0]=='+' else -int(ms.group(2)[1:],16)
                if breg not in ('rbp','rsp') and vreg in live and off>=0: found.append((live[vreg],G,off))
                continue
            ml=_P4_LOADF.match(ins)
            if ml and ml.group(2) in ('rbp','rsp'):
                dd=nrm(ml.group(1)); slot=ml.group(2)+ml.group(3)
                if slot in aslots: live[dd]=aslots[slot]
                else: live.pop(dd,None)
                continue
            mr=re.match(r'^mov\s+(r[a-z0-9]+|e[a-z][a-z]),(r[a-z0-9]+|e[a-z][a-z])$',ins)
            if mr:
                s=nrm(mr.group(2)); dd=nrm(mr.group(1))
                if s in live: live[dd]=live[s]
                else: live.pop(dd,None)
                continue
            m=P4_DEST.match(ins)
            if m and not ins.startswith(('cmp','test','push')): live.pop(nrm(m.group(1)),None)
        if found: out[fn]=found
    return out
def _p4_resolvers(recs_by_fn):
    """fn -> [(global_abs, off)]: returns a value loaded from a global-backed table entry."""
    out={}
    for fn,recs in recs_by_fn.items():
        if len(recs)>80: continue
        G=_p4_dominant_global(recs)
        if G is None: continue
        for r in recs:
            ml=_P4_LOADF.match(r["instruction"])
            if ml and nrm(ml.group(1))=="rax" and ml.group(2) not in ('rbp','rsp'):
                off=int(ml.group(3),16) if ml.group(3)[0]=='+' else -int(ml.group(3)[1:],16)
                if off>=0: out.setdefault(fn,[]).append((G,off))
    return out
def _p4_feeds_registrar(insns, read_ow, reg_table):
    """E routes a READ-open fd into a registrar's fd arg -> set of (G,off) tables E fills."""
    fd_slots=set(); hits=set()
    for _ in range(2):
        fd=set()
        for idx,ins in enumerate(insns):
            c=_p4_callee(ins)
            if c is not None:
                if c in reg_table:
                    for ai,G,off in reg_table[c]:
                        if ai<len(P4_ARGREGS) and P4_ARGREGS[ai] in fd: hits.add((G,off))
                fd-=P4_CALLER_SAVED
                if c in read_ow: fd.add("rax")
                elif c in OPEN_FAMILY and _p4_raw_open_dir(insns,idx,c)=="read": fd.add("rax")
                continue
            m=re.match(r'mov\s+(r[a-z0-9]+|e[a-z][a-z]),(r[a-z0-9]+|e[a-z][a-z])$',ins)
            if m:
                s=nrm(m.group(2)); dd=nrm(m.group(1)); fd.add(dd) if s in fd else fd.discard(dd); continue
            m=re.match(r'mov\s+(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\],(r[a-z0-9]+|e[a-z][a-z])$',ins)
            if m:
                if nrm(m.group(3)) in fd: fd_slots.add(m.group(1)+m.group(2))
                continue
            m=re.match(r'mov\s+(r[a-z0-9]+|e[a-z][a-z]),(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\]$',ins)
            if m:
                dd=nrm(m.group(1)); slot=m.group(2)+m.group(3); fd.add(dd) if slot in fd_slots else fd.discard(dd); continue
            m=P4_DEST.match(ins)
            if m and not ins.startswith(('cmp','test','push')): fd.discard(nrm(m.group(1)))
    return hits
_P4_READFDARG={"read":"rdi","pread":"rdi","pread64":"rdi","readv":"rdi","recv":"rdi",
    "fread":"rcx","fread_unlocked":"rcx","fgets":"rdx","fgets_unlocked":"rdx",
    "getc":"rdi","fgetc":"rdi","getc_unlocked":"rdi","fgetc_unlocked":"rdi","getline":"rdx","getdelim":"rdx"}
def _p4_drains_resolver(insns, resolver_fns):
    """C routes a resolver's return (via regs/slots) into a content-read fd -> set of (G,off)."""
    hits=set(); reg={}; slot={}
    for ins in insns:
        c=_p4_callee(ins)
        if c is not None:
            if c in _P4_READFDARG and _P4_READFDARG[c] in reg: hits.add(reg[_P4_READFDARG[c]])
            for rr in list(reg):
                if rr in P4_CALLER_SAVED: reg.pop(rr,None)
            if c in resolver_fns: reg["rax"]=resolver_fns[c][0]
            continue
        m=re.match(r'mov\s+(r[a-z0-9]+|e[a-z][a-z]),(r[a-z0-9]+|e[a-z][a-z])$',ins)
        if m:
            s=nrm(m.group(2)); dd=nrm(m.group(1))
            if s in reg: reg[dd]=reg[s]
            else: reg.pop(dd,None)
            continue
        m=re.match(r'mov\s+(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\],(r[a-z0-9]+|e[a-z][a-z])$',ins)
        if m:
            sl=m.group(1)+m.group(2); r=nrm(m.group(3))
            if r in reg: slot[sl]=reg[r]
            else: slot.pop(sl,None)
            continue
        m=re.match(r'mov\s+(r[a-z0-9]+|e[a-z][a-z]),(?:QWORD PTR |DWORD PTR )?\[(rbp|rsp)([+-]0x[0-9a-fA-F]+)\]$',ins)
        if m:
            dd=nrm(m.group(1)); sl=m.group(2)+m.group(3)
            if sl in slot: reg[dd]=slot[sl]
            else: reg.pop(dd,None)
            continue
        m=P4_DEST.match(ins)
        if m and not ins.startswith(('cmp','test','push')): reg.pop(nrm(m.group(1)),None)
    return hits
# --- P4c queue-egress: model "append a file to a send queue" as a logical send ---
# For zero-copy / event-loop servers (lighttpd) the egress is a `sendfile` in a DECOUPLED
# fdevent-loop function, so there is no read->write taint to follow. Instead anchor on the
# sendfile: learn the struct field it reads its file fd from (the "mount point"), find the
# functions that WRITE that field (the chunkqueue-append family), and treat those as egress
# helpers — then the SAME P4a machinery flags the caller that owns a read-only open and hands
# the file to an append helper (= the request handler, not the generic sendfile plumbing).
# This is P3's send-buffer decomposition re-anchored from `send`'s buffer arg to `sendfile`'s
# in_fd arg. Inherits P3's offset-collision imprecision (a field offset is not type-checked).
P4_SENDFILE={"sendfile","sendfile64"}
def _p4_sendfile_mount_offsets(funcs):
    """struct offsets that feed sendfile's in_fd (arg1 = rsi/esi), direct [base+off] form."""
    offs=set()
    for insns in funcs.values():
        for i,ins in enumerate(insns):
            if _p4_callee(ins) in P4_SENDFILE:
                for k in range(i-1, max(-1,i-8), -1):
                    m=re.match(r'mov (?:esi|rsi),(?:DWORD PTR |QWORD PTR )?\[(r[a-z0-9]+)([+-]0x[0-9a-fA-F]+)\]$',insns[k])
                    if m:
                        off=int(m.group(2),16) if m.group(2)[0]=='+' else -int(m.group(2)[1:],16)
                        if off>0: offs.add(off)
                        break
                    if re.match(r'mov (?:esi|rsi),',insns[k]): break
    return offs
def _p4_mount_writers(funcs, offs):
    pats=[re.compile(rf'^mov\s+(?:QWORD PTR |DWORD PTR )?\[(r[a-z0-9]+)\+0x{o:x}\],') for o in offs]
    out=set()
    for fn,insns in funcs.items():
        for ins in insns:
            if any(p.match(ins) for p in pats):
                m=re.match(r'^mov\s+(?:QWORD PTR |DWORD PTR )?\[(r[a-z0-9]+)\+',ins)
                if m and m.group(1) not in ('rsp','rbp'): out.add(fn); break
    return out
def _p4_up_closure(cg, seed, K):
    rev=defaultdict(set)
    for fn,cs in cg.items():
        for c in cs: rev[c].add(fn)
    dist={fn:0 for fn in seed}; dq=deque(seed)
    while dq:
        u=dq.popleft()
        for p in rev.get(u,()):
            if p not in dist and dist[u]+1<=K: dist[p]=dist[u]+1; dq.append(p)
    return set(dist)
def p4_fd_delegation(prog, funcs):
    """Return {fn: tag} for fd-delegation endpoints. tag in {'fd_arg','fd_table','fd_queue'}."""
    cg=_p4_callees(funcs)
    OW=_p4_open_wrappers(funcs,cg); read_ow=_p4_read_open_wrappers(funcs,cg,OW)
    rr=_p4_reach(funcs,cg,P4_READ,3); rw=_p4_reach(funcs,cg,P4_EXTWRITE,3)
    TH={fn for fn in funcs if fn in rr and fn in rw}
    out={}
    for fn,insns in funcs.items():
        if _p4_argpass(insns,read_ow,TH): out[fn]="fd_arg"
    # P4b handle-table
    recs=_p4_load_recs(prog)
    if recs:
        reg=_p4_registrars(recs); res=_p4_resolvers(recs)
        tables={(G,o) for v in reg.values() for _,G,o in v} & {k for v in res.values() for k in v}
        reg2={fn:[(ai,G,o) for ai,G,o in v if (G,o) in tables] for fn,v in reg.items()}
        reg2={k:v for k,v in reg2.items() if v}
        res2={fn:[k for k in v if k in tables] for fn,v in res.items()}
        res2={k:v for k,v in res2.items() if v}
        for fn,insns in funcs.items():
            if _p4_feeds_registrar(insns,read_ow,reg2): out.setdefault(fn,"fd_table")
            elif _p4_drains_resolver(insns,res2) and fn in rw: out.setdefault(fn,"fd_table")
    # P4c queue-egress (sendfile-anchored logical send)
    offs=_p4_sendfile_mount_offsets(funcs)
    if offs:
        egress_q=_p4_up_closure(cg, _p4_mount_writers(funcs,offs), 2)
        for fn,insns in funcs.items():
            if _p4_argpass(insns,read_ow,egress_q): out.setdefault(fn,"fd_queue")
    return out

def run(prog):
    funcs,structs=load(prog)
    if funcs is None: return None
    B=recall_B(funcs)
    endpoints={}
    for fn in funcs:
        h2=p2_samefunc(funcs[fn])
        if h2: endpoints[fn]=("samefunc",h2)
        # NOTE: p2_charloop (getc/putc) stays UNWIRED — within one function it cannot tell a
        # download (file->socket) from an upload (socket->file); direction is resolved by P4's
        # read-only-open origin filter instead (see p4_fd_delegation).
    for fn,c in p3_crossfunc(funcs,structs).items():
        if fn not in endpoints: endpoints[fn]=("crossbuf",c)
    for fn,tag in p4_fd_delegation(prog,funcs).items():
        if fn not in endpoints: endpoints[fn]=(tag,None)
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
