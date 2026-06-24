#!/usr/bin/env python3
"""Train the FINAL binary sink-detection model and save model + feature spec +
metrics. All features are binary-derived (objdump/DWARF); source is used only to
build labels (the dataset CSV), never for inference.

Feature groups (279 total):
  base        : columns in the dataset CSV (CFG + bin-eff + bin-reach + rodata
                strings + DWARF params + anti-FP flags + heuristic gate)
  name        : 30 generic security keyword flags over the DWARF function name
  dwarf_rich  : source-file / param-name / param-type keyword flags
  struct_local: local-variable / struct-type keyword flags
"""
import csv, json, sys
from pathlib import Path
import numpy as np
import xgboost as xgb
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import precision_recall_curve, confusion_matrix

HERE = Path(__file__).resolve().parent
REL = HERE.parent
# prefer the bundled data/ jsons (self-contained); fall back to the repo ml_dataset/
ML = REL / "data" if (REL / "data" / "dwarf_rich_features.json").exists() else REL.parent / "ml_dataset"
DATA = REL / "dataset" / "integrated_function_features.csv"

NAME_KW = ['auth','passwd','password','pubkey','cred','login','verify','access','perm','policy',
 'sudoers','cmnd','command','refer','privile','principal','allow','deny','permit','grant','secure',
 'session','ident','token','sign','chroot','setuid','exec','match','check']

def load():
    rows = list(csv.DictReader(open(DATA)))
    base = [c for c in rows[0].keys() if c not in ("target_id","function","y")]
    DR = json.load(open(ML/"dwarf_rich_features.json"))
    LS = json.load(open(ML/"dwarf_struct_local_features.json"))
    drc = sorted({k for p in DR.values() for f in p.values() for k in f})
    lsc = sorted({k for p in LS.values() for f in p.values() for k in f})
    def vec(r):
        nm = r['function'].lower()
        name = [1.0 if k in nm else 0.0 for k in NAME_KW]
        dr = [float(DR.get(r['target_id'],{}).get(r['function'],{}).get(c,0)) for c in drc]
        ls = [float(LS.get(r['target_id'],{}).get(r['function'],{}).get(c,0)) for c in lsc]
        return [float(r[c]) for c in base] + name + dr + ls
    X = np.array([vec(r) for r in rows]); y = np.array([int(r['y']) for r in rows])
    tids = np.array([r['target_id'] for r in rows])
    cols = base + [f"name_{k}" for k in NAME_KW] + drc + lsc
    return X, y, tids, cols, base, drc, lsc

PARAMS = dict(objective="binary:logistic", eta=0.05, max_depth=5, subsample=0.85,
              colsample_bytree=0.8, tree_method="hist", seed=42, verbosity=0)

def main():
    X, y, tids, cols, base, drc, lsc = load()
    print(f"dataset: {len(y)} functions, {int(y.sum())} sinks / {int((y==0).sum())} non-sinks, {len(cols)} features")
    # 5-fold confusion matrix + threshold
    s = np.zeros(len(y))
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=42).split(X, y):
        b = xgb.train(PARAMS, xgb.DMatrix(X[tr], label=y[tr]), 300, verbose_eval=False)
        s[te] = b.predict(xgb.DMatrix(X[te]))
    P, R, T = precision_recall_curve(y, s); j = int(np.argmax(np.minimum(P[:-1], R[:-1]))); thr = float(T[j])
    pred = (s >= thr).astype(int); tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    # LOPO balanced
    sl = np.zeros(len(y))
    for h in sorted(set(tids)):
        trn = np.where(tids != h)[0]; ten = np.where(tids == h)[0]
        if y[ten].sum() == 0: continue
        b = xgb.train(PARAMS, xgb.DMatrix(X[trn], label=y[trn]), 300, verbose_eval=False)
        sl[ten] = b.predict(xgb.DMatrix(X[ten]))
    Pl, Rl, _ = precision_recall_curve(y, sl); jl = int(np.argmax(np.minimum(Pl[:-1], Rl[:-1])))
    # train final model on ALL data, save
    final = xgb.train(PARAMS, xgb.DMatrix(X, label=y, feature_names=cols), 300, verbose_eval=False)
    final.save_model(str(REL/"model"/"sink_model.json"))
    json.dump({"feature_order": cols, "base_csv_columns": base, "name_keywords": NAME_KW,
               "dwarf_rich_columns": drc, "struct_local_columns": lsc,
               "threshold": thr, "n_features": len(cols)},
              open(REL/"model"/"feature_spec.json","w"), indent=2)
    metrics = {"dataset": {"functions": len(y), "sinks": int(y.sum()), "non_sinks": int((y==0).sum())},
        "operating_threshold": round(thr,3),
        "pooled_5fold": {"TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn),
                         "precision": round(tp/(tp+fp),3), "recall": round(tp/(tp+fn),3),
                         "f1": round(2*tp/(2*tp+fp+fn),3), "accuracy": round((tp+tn)/len(y),3)},
        "cross_program_LOPO": {"balanced_precision": round(float(Pl[jl]),3),
                               "balanced_recall": round(float(Rl[jl]),3),
                               "note": "honest cross-program number (held-out whole program)"}}
    json.dump(metrics, open(REL/"model"/"metrics.json","w"), indent=2)
    print(json.dumps(metrics, indent=2))
    print("saved model/, feature_spec.json, metrics.json")

if __name__ == "__main__":
    main()
