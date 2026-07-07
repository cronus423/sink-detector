#!/usr/bin/env python3
"""Binary-grounded effect features (fixes the nginx-macro blind spot).

Source-based eff features missed nginx because nginx issues effects via inline
MACROS (ngx_open_file -> open) that don't textually match `open(`. But the macro
expands in the BINARY: the real `call open@plt` / `call execve@plt` sits inside
the calling function. So we read effect calls straight from the disassembly —
uniform across all programs, no per-program idiom recognition needed.

Emits ml_dataset/bin_effect_features.json: { program: { func: {eff_<cat>, ...} } }
Same schema as effect_call_features so it can drop into build_integrated_dataset.
"""
import json, re, sys
from pathlib import Path
from collections import defaultdict
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import callgraph_reach_features as CG

REPO = CG.ROOT.parent
def disasm_path(prog):
    if prog == "nginx_1_4_0_validation":
        return REPO/"nginx_1_4_0_validation/artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"
    return CG.ROOT/prog/"artifacts/stage_02_static_ir_cfg/nginx_disassembly.jsonl"

# auxiliary stage_02 dirs (plugins/.so analyzed separately) folded in per program
EXTRA_STAGE02 = {"sudo_1_8_31": ["stage_02_sudoers_plugin"]}
def disasm_paths(prog):
    out = [disasm_path(prog)]
    for a in EXTRA_STAGE02.get(prog, []):
        p = CG.ROOT/prog/"artifacts"/a/"nginx_disassembly.jsonl"
        if p.exists(): out.append(p)
    return [p for p in out if p.exists()]

def dwarf_names_all(prog):
    names = set(CG.dwarf_names(CG.DWARF[prog]))
    for a in EXTRA_STAGE02.get(prog, []):
        p = CG.ROOT/prog/"artifacts"/a/"dwarf_facts.json"
        if p.exists():
            d = json.loads(p.read_text())
            names |= {v["name"] for v in d.get("functions",{}).values()
                      if isinstance(v,dict) and v.get("name")}
    return names

CATS = ["privilege_identity","capability","exec","file_mutation","mount","rlimit"]
# binary libc/syscall symbol -> effect category (includes 64/at variants)
EFFECT = {}
def add(names, cat):
    for n in names: EFFECT[n]=cat
add(["setuid","seteuid","setreuid","setresuid","setgid","setegid","setregid","setresgid",
     "setgroups","initgroups","setfsuid","setfsgid"], "privilege_identity")
add(["capset","capsetp","cap_set_proc","prctl","chroot","pivot_root","unshare","setns"], "capability")
add(["mount","umount","umount2"], "mount")
add(["execve","execv","execvp","execvpe","execl","execlp","execle","fexecve","execveat",
     "system","popen","posix_spawn","posix_spawnp","dlopen"], "exec")
add(["chmod","fchmod","fchmodat","chown","fchown","lchown","fchownat","unlink","unlinkat",
     "rename","renameat","renameat2","link","linkat","symlink","symlinkat","mkdir","mkdirat",
     "rmdir","mknod","truncate","ftruncate","creat","creat64","open","open64","openat","openat64"],
    "file_mutation")
add(["setrlimit","prlimit","prlimit64","setpriority"], "rlimit")

# `file_read` = content-DISCLOSURE reads. Kept as a SEPARATE set (not in EFFECT)
# because open*/creat* are already `file_mutation` yet an open-for-read is also a
# read; a function can be both. Detected the same way (direct call target). See
# docs/SINK_LABELING_STANDARD.md effect taxonomy.
FILEREAD = set("""read pread pread64 readv preadv fread fread_unlocked fgets
fgets_unlocked fgetc getc getc_unlocked getline getdelim fscanf __isoc99_fscanf
mmap mmap64 sendfile sendfile64 opendir fdopendir readdir readdir64 readdir_r
scandir scandir64 fopen fopen64 freopen freopen64 fdopen open open64 openat
openat64""".split())

SYM = re.compile(r'<([^>+@]+)')

def main():
    out = {}
    for prog in CG.SRC:
        paths = disasm_paths(prog)
        if not paths:
            print(f"{prog:24s} NO DISASM"); continue
        cnt = defaultdict(lambda: defaultdict(int))
        for p in paths:
          with p.open() as f:
            for line in f:
                if "call" not in line: continue
                r = json.loads(line)
                ins = r.get("instruction","")
                if not ins.startswith("call"): continue
                m = SYM.search(ins)
                if not m: continue
                tgt = m.group(1).strip()
                cat = EFFECT.get(tgt)
                if cat: cnt[r["function"]][cat]+=1
                if tgt in FILEREAD: cnt[r["function"]]["file_read"]+=1
        feats={}
        for fn,cc in cnt.items():
            row={f"eff_{c}":int(cc.get(c,0)) for c in CATS}
            row["eff_total"]=int(sum(cc.get(c,0) for c in CATS))
            row["eff_ncats"]=int(sum(1 for c in CATS if cc.get(c)))
            row["eff_file_read"]=int(cc.get("file_read",0))
            feats[fn]=row
        out[prog]=feats
        print(f"{prog:24s} functions with binary effect calls: {len(feats)}")
    (CG.ROOT/"ml_dataset"/"bin_effect_features.json").write_text(json.dumps(out,indent=2))
    print("wrote ml_dataset/bin_effect_features.json")

if __name__=="__main__":
    main()
