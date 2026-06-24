#!/usr/bin/env python3
"""Inference: rank a target's functions by sink probability.

Usage:  python3 scan_binary.py <target_id> [threshold]
        python3 scan_binary.py --list                 # show available targets

Self-contained: reads the pre-extracted feature table data/all_function_features.csv
(every DWARF function x 279 binary features) and the shipped model. Needs NO
stage_02 artifacts and NO build_curated machinery.

To scan a brand-NEW binary (not in the table): build it with -g, run the DFB
stage_02 pipeline + the feature_extractors to extend the table, then scan. See
README section "Scanning a new binary".
"""
import csv, json, sys
from pathlib import Path
import numpy as np
import xgboost as xgb

REL = Path(__file__).resolve().parents[1]
spec = json.load(open(REL / "model" / "feature_spec.json"))
order = spec["feature_order"]
TABLE = REL / "data" / "all_function_features.csv"


def load_table():
    rows = {}
    for r in csv.DictReader(open(TABLE)):
        rows.setdefault(r["target_id"], []).append(r)
    return rows


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__); return
    table = load_table()
    if sys.argv[1] == "--list":
        for t in sorted(table):
            print(f"  {t:28s} {len(table[t])} functions")
        return
    t = sys.argv[1]
    thr = float(sys.argv[2]) if len(sys.argv) > 2 else spec["threshold"]
    if t not in table:
        print(f"target '{t}' not in {TABLE.name}. Available: {', '.join(sorted(table))}")
        sys.exit(1)
    model = xgb.Booster(); model.load_model(str(REL / "model" / "sink_model.json"))
    rows = table[t]
    X = np.array([[float(r[c]) for c in order] for r in rows])
    s = model.predict(xgb.DMatrix(X, feature_names=order))
    scored = sorted(((float(s[i]), rows[i]["function"]) for i in range(len(rows))), reverse=True)
    flagged = [x for x in scored if x[0] >= thr]
    print(f"=== {t}: {len(rows)} functions scanned | threshold {thr:.3f} | flagged as sink: {len(flagged)} ===")
    for sc, fn in flagged:
        print(f"  {sc:.3f}  {fn}")


if __name__ == "__main__":
    main()
