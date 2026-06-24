#!/usr/bin/env python3
"""Apply SINK_LABELING_STANDARD uniformly to ALL programs, binary-derived.

Hypothesis: the pooled metric is capped at ~0.65 because only nginx was relabeled
to concrete granularity; the other programs keep codex's mixed (handler+concrete+
dispatch) labels. Make labels CONSISTENT across all programs.

Concrete-granularity POSITIVE (binary-derivable):
  - directly issues a real effect in the binary (bin_effect: exec/privilege/
    capability/file_mutation/network; NOT rlimit-only), AND
  - has real logic (num_instructions >= MIN_INSN -> not a thin syscall wrapper),
  - excluding self-cleanup/lifecycle name patterns.
  PLUS authz decision sinks kept from codex labels (name-matched).
NEGATIVE = prior negatives (curated non-sink + codex false_sink) + demoted
  (old positives that are not concrete effect issuers).
"""
import csv, json, re, sys
from pathlib import Path
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import build_curated_function_feature_dataset as B
import build_integrated_dataset as I

MIN_INSN = 8
BIN = I.BIN
REAL = ["eff_exec","eff_privilege_identity","eff_capability","eff_file_mutation"]  # non-rlimit, non-mount-only
CLEANUP = re.compile(r'cleanup|_free$|destroy|_exit|pidfile|scoreboard|reset|disallow', re.I)  # dropped over-broad remove$/delete
# authz DECISION sinks (apply by name across ALL programs)...
AUTHZ = re.compile(r'auth|passwd|password|pubkey|verify|sudoers|cmnd|referer|referrer|principal|access|chkpass', re.I)
# ...but EXCLUDE auth bookkeeping (logging/cache/lookup/io), not decisions
BOOKKEEP = re.compile(r'log|cache|record|send|recv|_get|_set|free|init|reset|dump|msg|scheme|banner|info|count|notify|debug', re.I)

def num_insn(cfg, fn):
    sn, c = B.find_cfg_function(cfg, fn)
    if c is None: return 0
    return len(c.get("instructions", c.get("blocks", []))) if isinstance(c, dict) else 0

def main():
    pos0, neg0, cfg_cache = I.gather()                 # codex/recall labels
    # add HTTP siblings + nginx concrete (already curated lists) so they aren't lost
    from add_extra_program_rows import LABELS as EXTRA
    import relabel_nginx as RN
    extra_pos = {t:set(v["pos"]) for t,v in EXTRA.items()}
    extra_pos.setdefault("nginx_1_4_0_validation", set()).update(RN.POS)
    progs = sorted(set(list(pos0)+list(neg0)+list(extra_pos)+list(BIN)))

    cfgc = {t: B.load_cfg_sources(t) for t in B.TARGET_TO_TITLE if t in progs}
    def cfg(t):
        return cfgc.get(t) or B.load_cfg_sources(t)

    new_pos, new_neg = {}, {}
    for t in progs:
        be = BIN.get(t, {})
        # concrete effect issuers (real effect, real logic, not cleanup)
        concrete = set()
        for fn, e in be.items():
            if any(e.get(c,0) for c in REAL):
                if CLEANUP.search(fn): continue
                if num_insn(cfg(t), fn) >= MIN_INSN:
                    concrete.add(fn)
        # authz decision sinks BY NAME across ALL programs (bold DWARF-name use):
        # name looks like an auth/policy decision, not bookkeeping, and resolvable.
        dwnames=set()
        for _,ss in B.load_dwarf_sources(t): dwnames|=ss
        authz={fn for fn in dwnames
               if AUTHZ.search(fn) and not BOOKKEEP.search(fn)
               and num_insn(cfg(t),fn) >= MIN_INSN}
        P = concrete | authz | (extra_pos.get(t,set()) & set(be))   # keep curated concrete
        # restrict to resolvable
        P = {fn for fn in P if I.feats(t, fn, cfgc if t in cfgc else {t:cfg(t)}) is not None} \
            if False else P
        # negatives: prior neg + demoted old positives
        old_pos = pos0.get(t,set()) | extra_pos.get(t,set())
        N = (neg0.get(t,set()) | (old_pos - P)) - P
        # new programs (no codex negatives): sample non-effect DWARF functions as negatives
        if len(N) < 4*max(len(P),1):
            import random
            names=set()
            for _,ss in B.load_dwarf_sources(t): names|=ss
            cand=[fn for fn in names if fn not in P and fn not in N
                  and I.feats(t,fn,{t:cfg(t)}) is not None]
            random.Random(42).shuffle(cand)
            N |= set(cand[:4*max(len(P),1)-len(N)])
        new_pos[t]=P; new_neg[t]=N

    # build rows
    cols = I.STRICT + I.EFF_COLS + I.REACH_COLS + I.ST_COLS
    rows=[]
    for t in progs:
        cc = {t: cfg(t)}
        for label, fns in ((1,new_pos[t]),(0,new_neg[t])):
            for fn in fns:
                f = I.feats(t, fn, cc)
                if f is None: continue
                rows.append([t,fn,label]+[f[k] for k in cols])
    # dedup (pos wins)
    seen=set(); out=[]
    rows.sort(key=lambda r:-r[2])
    for r in rows:
        if (r[0],r[1]) in seen: continue
        seen.add((r[0],r[1])); out.append(r)
    with (B.ML_DATASET/"integrated_function_features.csv").open("w",newline="") as fh:
        w=csv.writer(fh); w.writerow(["target_id","function","y"]+cols)
        for r in out: w.writerow(r)
    npos=sum(1 for r in out if r[2]==1)
    print(f"UNIFORM CONCRETE RELABEL: {len(out)} rows, {npos} pos / {len(out)-npos} neg")
    from collections import Counter
    c=Counter((r[0],r[2]) for r in out)
    for t in progs: print(f"   {t:24s} pos={c.get((t,1),0):4d} neg={c.get((t,0),0):4d}")

if __name__=="__main__":
    main()
