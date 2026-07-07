#!/usr/bin/env python3
"""Integrated sink pipeline: XGBoost coarse-screen  ->  P1 recall candidates  ->
subtract what XGBoost already found  ->  P2-P5 discriminate the remainder  ->  union.

    final_sinks = S_xgb  ∪  { P2-P5 endpoints  ∩  (recall_B − S_xgb) }

XGBoost is the broad attack-sink detector (privilege/exec/file-mutation/file-read).
P1-P5 (endpoint_detector) is the file-read-disclosure recall booster for the class
XGBoost's per-function features structurally miss. This driver chains them as designed
instead of running them side by side.

Usage:  python3 pipeline.py [prog ...]      # default: all file-read GT programs
"""
import csv, json, sys
from pathlib import Path
import numpy as np, xgboost as xgb
import endpoint_detector.detector as D

REL = Path(__file__).resolve().parent
_spec = json.load(open(REL / "model" / "feature_spec.json"))
_order = _spec["feature_order"]; _THR = _spec["threshold"]
_model = xgb.Booster(); _model.load_model(str(REL / "model" / "sink_model.json"))
_FEAT = {}
for _r in csv.DictReader(open(REL / "data" / "all_function_features.csv")):
    _FEAT.setdefault(_r["target_id"], []).append(_r)


def xgb_screen(prog):
    """S_xgb: functions XGBoost flags as sinks. None if prog has no feature rows."""
    rows = _FEAT.get(prog)
    if not rows:
        return None
    X = np.array([[float(r.get(c, 0) or 0) for c in _order] for r in rows])
    s = _model.predict(xgb.DMatrix(X, feature_names=_order))
    return {rows[i]["function"] for i in range(len(rows)) if s[i] >= _THR}


def integrated(prog):
    """Return dict with the staged sets of the integrated pipeline."""
    r = D.run(prog)
    if r is None:
        return None
    B, endpoints = r                       # P1 recall set + P2-P5 endpoints
    s_xgb = xgb_screen(prog)
    xgb_avail = s_xgb is not None
    s_xgb = s_xgb or set()
    cand = set(B) - s_xgb                   # recall candidates XGBoost did NOT cover
    s_gap = {fn: tag for fn, (tag, _) in endpoints.items() if fn in cand}
    final = s_xgb | set(s_gap)
    return {"B": set(B), "xgb_avail": xgb_avail, "s_xgb": s_xgb,
            "cand": cand, "s_gap": s_gap, "final": final}


def main():
    progs = sys.argv[1:] or list(D.GT)
    print(f"{'program':22s} {'XGB':>5s} {'|B|':>5s} {'cand':>5s} {'P1-5+':>6s} {'final':>6s}"
          f"   {'FR-GT':>5s} {'TP':>3s} {'FN':>3s}  recovered-by-P1-5")
    tot = {"tp": 0, "fn": 0, "gap_gt": 0}
    for prog in progs:
        r = integrated(prog)
        if r is None:
            print(f"{prog:22s}  no artifacts"); continue
        gt = set(D.GT.get(prog, []))
        tp = gt & r["final"]; fn = gt - r["final"]
        gap_gt = gt & set(r["s_gap"])          # GT sinks P1-P5 recovered (XGB missed)
        tot["tp"] += len(tp); tot["fn"] += len(fn); tot["gap_gt"] += len(gap_gt)
        xg = str(len(r["s_xgb"])) if r["xgb_avail"] else "n/a"
        print(f"{prog:22s} {xg:>5s} {len(r['B']):5d} {len(r['cand']):5d} {len(r['s_gap']):6d} "
              f"{len(r['final']):6d}   {len(gt):5d} {len(tp):3d} {len(fn):3d}  {sorted(gap_gt)}")
    print(f"\nfile-read GT recall (integrated) = {tot['tp']}/{tot['tp']+tot['fn']}"
          f"  | of which recovered by P1-P5 (XGB missed) = {tot['gap_gt']}")


if __name__ == "__main__":
    main()
