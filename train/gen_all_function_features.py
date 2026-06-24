#!/usr/bin/env python3
"""One-time: dump the full 279-feature vector for EVERY DWARF function of every
program into a single compact table (data/all_function_features.csv).

This is what makes the release self-contained: after this runs, inference
(`inference/scan_binary.py`) reads the table directly and needs NEITHER the
2.7 GB of per-target stage_02 artifacts NOR the repo's build_curated machinery.

Run from program_targets/ (needs the repo stage_02 artifacts + feature jsons).
"""
import csv, json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REL = HERE.parent
# One-time generator: import the REPO originals (their paths resolve to the
# stage_02 artifacts). The copies under train/ are handoff reference only.
sys.path.insert(0, str(REL.parent / "scripts"))
import build_curated_function_feature_dataset as B
import build_integrated_dataset as I
import callgraph_reach_features as CG

ML = REL.parent / "ml_dataset"
spec = json.load(open(REL / "model" / "feature_spec.json"))
DR = json.load(open(ML / "dwarf_rich_features.json"))
LS = json.load(open(ML / "dwarf_struct_local_features.json"))
order = spec["feature_order"]


def vec(t, fn, cfgc):
    base = I.feats(t, fn, cfgc)
    if base is None:
        return None
    f = dict(base)
    nm = fn.lower()
    for k in spec["name_keywords"]:
        f[f"name_{k}"] = 1.0 if k in nm else 0.0
    dr = DR.get(t, {}).get(fn, {})
    ls = LS.get(t, {}).get(fn, {})
    for c in spec["dwarf_rich_columns"]:
        f[c] = float(dr.get(c, 0))
    for c in spec["struct_local_columns"]:
        f[c] = float(ls.get(c, 0))
    return [float(f.get(c, 0.0)) for c in order]


def main():
    out_path = REL / "data" / "all_function_features.csv"
    out_path.parent.mkdir(exist_ok=True)
    w = csv.writer(open(out_path, "w", newline=""))
    w.writerow(["target_id", "function"] + order)
    n_funcs = 0
    for t in CG.SRC:
        try:
            cfgc = {t: B.load_cfg_sources(t)}
            dw = B.read_json(B.target_artifact_dir(t) / "dwarf_facts.json")
        except Exception as e:
            print(f"  skip {t}: {e}")
            continue
        names = sorted({v["name"] for v in dw["functions"].values()
                        if isinstance(v, dict) and v.get("name")})
        k = 0
        for fn in names:
            v = vec(t, fn, cfgc)
            if v is None:
                continue
            w.writerow([t, fn] + v)
            k += 1
        n_funcs += k
        print(f"  {t:24s} {k} functions")
    print(f"wrote {out_path}  ({n_funcs} functions x {len(order)} features)")


if __name__ == "__main__":
    main()
