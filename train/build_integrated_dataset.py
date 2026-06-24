#!/usr/bin/env python3
"""Integrated function-level attack-endpoint dataset (user-directed merge).

POSITIVES = union of:
  - curated worth_attack=1 (the original 84 training seeds)
  - codex review true_sink (the ~475 reviewed sinks, previously NOT in training)
  - recall-audit CONFIRMED endpoints (recall_confirmed_endpoints.jsonl, 22)
NEGATIVES = union of:
  - curated non-sink (49)
  - codex review false_sink (~1222 human-reviewed negatives, previously unused)
FEATURES = 125 binary_only (codex extractors) + 8 eff-call (wrapper-aware)
           + 10 callgraph-to-effect reachability (transitive; the cross-program win)
           + 13 string/constant + arg-taint proxy (within-program refinement). = 156

Writes CSV + manifest, then trains XGBoost with 5-fold CV and leave-one-program
-out (honest cross-program generalization). One row per function (function-level).
"""
from __future__ import annotations
import csv, json, sys
from pathlib import Path
from collections import defaultdict
import numpy as np

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import build_curated_function_feature_dataset as B   # cfg/dwarf/feature machinery (handles nginx paths)

ML = B.ML_DATASET
SCANS = ML / "program_scans"
STRICT = B.read_json(B.STRICT_FEATURE_LIST)["ordered_feature_names"]
# ARCHITECTURE RULE: feature/semantic extraction is BINARY-only (DWARF binary),
# never source. Source is allowed only for building labels (dataset construction).
BIN = json.loads((ML / "bin_effect_features.json").read_text())    # binary direct effect calls
EFF_COLS = ["eff_privilege_identity","eff_capability","eff_exec","eff_file_mutation",
            "eff_mount","eff_rlimit","eff_total","eff_ncats"]
def eff_feats(t, fn):
    b = BIN.get(t,{}).get(fn,{})
    return {c: float(b.get(c,0)) for c in EFF_COLS}
RCH = json.loads((ML / "bin_reach_features.json").read_text())     # binary callgraph reachability
_RCATS = ["privilege_identity","capability","exec","file_mutation","mount","rlimit"]
REACH_COLS = [f"reach_{c}" for c in _RCATS] + ["reach_any","reach_ncats","reach_dist","reach_neff_callees"]
def reach_feats(t, fn):
    r = RCH.get(t, {}).get(fn)
    if r is None:
        return {c: 0.0 for c in REACH_COLS[:-2]} | {"reach_dist": 99.0, "reach_neff_callees": 0.0}
    return {c: float(r.get(c, 0)) for c in REACH_COLS}
BSTR = json.loads((ML / "bin_string_features.json").read_text())   # rodata strings (binary)
_SCOLS = ["s_count","s_path","s_syspath","s_shell","s_cred","s_cap","s_fmt"]
ST_COLS = _SCOLS + ["p_nparam","p_nptr"]   # binary rodata strings + DWARF param inflow
_DWP = {}
def _dwarf_params(t):
    if t in _DWP: return _DWP[t]
    import build_curated_function_feature_dataset as _B
    d = _B.read_json(_B.target_artifact_dir(t)/"dwarf_facts.json")
    m = {}
    for v in d.get("functions",{}).values():
        if isinstance(v,dict) and v.get("name"):
            ps = v.get("params",[])
            m[v["name"]] = (len(ps), sum(1 for p in ps if p.get("is_pointer")))
    _DWP[t] = m; return m
def st_feats(t, fn):
    np_, nptr = _dwarf_params(t).get(fn, (0,0))
    s = BSTR.get(t,{}).get(fn,{})
    out = {c: float(s.get(c,0)) for c in _SCOLS}
    out["p_nparam"]=float(np_); out["p_nptr"]=float(nptr)
    return out
OUT_CSV = ML / "integrated_function_features.csv"
OUT_MANIFEST = ML / "integrated_dataset_manifest.json"


def review_labels(prog):
    pos, neg = set(), set()
    for fn in ("unlabeled_source_review.csv","likely_sink_add_source_review.csv"):
        p = SCANS / prog / fn
        if p.exists():
            with p.open() as f:
                rd = csv.DictReader(f); col = rd.fieldnames[0]
                vc = "source_verdict" if "source_verdict" in rd.fieldnames else rd.fieldnames[1]
                for r in rd:
                    (pos if r[vc]=="true_sink" else neg).add(r[col])
            break
    return pos, neg


def gather():
    cfg_cache = {t: B.load_cfg_sources(t) for t in B.TARGET_TO_TITLE}
    pos, neg = defaultdict(set), defaultdict(set)
    # 1. curated positives
    for line in B.CURATED_SINKS_JSONL.read_text().splitlines():
        if not line.strip(): continue
        rec = json.loads(line)
        if rec.get("label",{}).get("worth_attack") != 1: continue
        t = rec["target_id"]
        fn,_ = B.resolve_positive_function(rec, B.merged_cfg_names(cfg_cache[t]))
        if fn: pos[t].add(fn)
    # 2. curated non-sinks
    for rec in B.parse_non_sinks(): neg[rec["target_id"]].add(rec["function"])
    # 3. codex review true/false
    for t in B.TARGET_TO_TITLE:
        rp, rn = review_labels(t)
        pos[t] |= rp; neg[t] |= rn
    # 4. recall-audit confirmed
    for line in (SCANS/"recall_confirmed_endpoints.jsonl").read_text().splitlines():
        if line.strip():
            r = json.loads(line); pos[r["program"]].add(r["function"])
    # negatives never override positives
    for t in neg: neg[t] -= pos.get(t,set())
    return pos, neg, cfg_cache


def feats(t, fn, cfg_cache):
    sn, fcfg = B.find_cfg_function(cfg_cache[t], fn)
    if fcfg is None or not B.has_dwarf_name(B.load_dwarf_sources(t), fn):
        return None
    f = B.extract_binary_features(fcfg, STRICT)
    f.update(eff_feats(t, fn))
    f.update(reach_feats(t, fn))
    f.update(st_feats(t, fn))
    # explicit anti-FP features (derived from the above; still 100% binary)
    real = f["eff_exec"]+f["eff_privilege_identity"]+f["eff_capability"]+f["eff_file_mutation"]+f["eff_mount"]
    f["f_only_rlimit"]   = 1.0 if (f["eff_rlimit"]>0 and real==0) else 0.0
    f["f_dispatcher"]    = 1.0 if (f["reach_any"]>0 and f["eff_total"]==0) else 0.0
    f["f_effect_no_ptr"] = 1.0 if (f["eff_total"]>0 and f["p_nptr"]==0) else 0.0
    # inter-procedural gating (targets authz/decision sinks: return branched-on, guards an effect)
    g = GATE.get(t,{}).get(fn,{})
    f["gate_branched"]   = float(g.get("gate_branched",0))
    f["gate_ncallers"]   = float(g.get("gate_ncallers",0))
    f["gate_eff_caller"] = float(g.get("gate_eff_caller",0))
    return f


ANTIFP_COLS = ["f_only_rlimit","f_dispatcher","f_effect_no_ptr"]
GATE_COLS = ["gate_branched","gate_ncallers","gate_eff_caller"]
GATE = json.loads((ML / "inter_gate_features.json").read_text()) if (ML/"inter_gate_features.json").exists() else {}


def build():
    pos, neg, cfg_cache = gather()
    rows, skipped = [], 0
    for label, table in ((1,pos),(0,neg)):
        for t, fns in table.items():
            for fn in fns:
                f = feats(t, fn, cfg_cache)
                if f is None: skipped += 1; continue
                rows.append({"target_id":t,"function":fn,"y":label,"feat":f})
    return rows, skipped


def cv_lopo(rows):
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    import xgboost as xgb
    cols = STRICT + EFF_COLS + REACH_COLS + ST_COLS
    X = np.array([[float(r["feat"][k]) for k in cols] for r in rows])
    y = np.array([r["y"] for r in rows])
    tids = [r["target_id"] for r in rows]
    params = dict(objective="binary:logistic", eta=0.05, max_depth=4, min_child_weight=1,
                  subsample=0.85, colsample_bytree=0.85, tree_method="hist", seed=42, verbosity=0)
    # 5-fold CV
    skf = StratifiedKFold(5, shuffle=True, random_state=42)
    cv = defaultdict(list)
    for tr,te in skf.split(X,y):
        bst = xgb.train(params, xgb.DMatrix(X[tr],label=y[tr],feature_names=cols), 250, verbose_eval=False)
        s = bst.predict(xgb.DMatrix(X[te],feature_names=cols)); pr=(s>=0.5).astype(int)
        cv["f1"].append(f1_score(y[te],pr)); cv["precision"].append(precision_score(y[te],pr,zero_division=0))
        cv["recall"].append(recall_score(y[te],pr)); cv["roc_auc"].append(roc_auc_score(y[te],s))
    cv = {k:round(float(np.mean(v)),4) for k,v in cv.items()}
    # LOPO
    ys, ps, per = [], [], {}
    for held in sorted(set(tids)):
        tr=[i for i,t in enumerate(tids) if t!=held]; te=[i for i,t in enumerate(tids) if t==held]
        if not te or y[te].sum()==0: continue
        bst=xgb.train(params, xgb.DMatrix(X[tr],label=y[tr],feature_names=cols),250,verbose_eval=False)
        s=bst.predict(xgb.DMatrix(X[te],feature_names=cols)); pr=(s>=0.5).astype(int)
        per[held]=dict(n=len(te),pos=int(y[te].sum()),
                       recall=round(float(recall_score(y[te],pr,zero_division=0)),3),
                       precision=round(float(precision_score(y[te],pr,zero_division=0)),3))
        ys+=y[te].tolist(); ps+=pr.tolist()
    ys,ps=np.array(ys),np.array(ps)
    lopo=dict(f1=round(float(f1_score(ys,ps)),4),precision=round(float(precision_score(ys,ps,zero_division=0)),4),
              recall=round(float(recall_score(ys,ps)),4), per_program=per)
    return cv, lopo


def main():
    rows, skipped = build()
    npos = sum(r["y"] for r in rows)
    cols = ["target_id","function","y"] + STRICT + EFF_COLS + REACH_COLS + ST_COLS
    with OUT_CSV.open("w", newline="") as f:
        w = csv.writer(f); w.writerow(cols)
        for r in rows:
            w.writerow([r["target_id"], r["function"], r["y"]] + [r["feat"][k] for k in STRICT+EFF_COLS+REACH_COLS+ST_COLS])
    perprog = defaultdict(lambda:[0,0])
    for r in rows: perprog[r["target_id"]][0 if r["y"]==1 else 1]+=1
    print(f"INTEGRATED DATASET: {len(rows)} rows, {npos} pos / {len(rows)-npos} neg "
          f"(1:{(len(rows)-npos)/npos:.2f}); {skipped} unresolved skipped")
    for t in sorted(perprog): print(f"   {t:24s} pos={perprog[t][0]:4d} neg={perprog[t][1]:4d}")
    cv, lopo = cv_lopo(rows)
    print(f"\n5-fold CV : f1={cv['f1']} prec={cv['precision']} recall={cv['recall']} roc_auc={cv['roc_auc']}")
    print(f"LOPO      : f1={lopo['f1']} prec={lopo['precision']} recall={lopo['recall']}")
    print("LOPO per-program (held-out):")
    for t,m in lopo["per_program"].items():
        print(f"   {t:24s} pos={m['pos']:4d} recall={m['recall']:.2f} precision={m['precision']:.2f}")
    OUT_MANIFEST.write_text(json.dumps({"rows":len(rows),"positives":npos,"negatives":len(rows)-npos,
        "features":len(STRICT)+len(EFF_COLS)+len(REACH_COLS)+len(ST_COLS),"cv":cv,"lopo":lopo,
        "per_program":{t:{"pos":v[0],"neg":v[1]} for t,v in perprog.items()}}, indent=2))
    print(f"\nwrote {OUT_CSV}\nwrote {OUT_MANIFEST}")


if __name__=="__main__":
    main()
