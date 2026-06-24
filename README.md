# sink_detector — function-level attack-sink detector for binaries

A model that, given a **binary with debug info (DWARF)**, predicts which functions
are **attack sinks** (attack endpoints: privilege/exec/file-mutation/capability
effects, and authorization/policy decisions).

**Design constraint (strict):** at **inference** the model uses *only* the binary
and its DWARF (objdump/readelf) — **no C source**. C source is used *only* to
build the training labels (the dataset CSV). The DWARF carries function names,
parameter names/types, and source-file names — all embedded in the binary, not
read from `.c` files.

---

## Final results

Model: a single **XGBoost** gradient-boosted-tree classifier, **279 binary
features**, trained on **2760 functions (524 sinks / 2236 non-sinks)** across
14 programs (HTTP, FTP, SSH, sudo/doas/polkit, DNS).

| Evaluation | Precision | Recall | F1 | Notes |
|---|--:|--:|--:|---|
| **Pooled 5-fold CV** (within-distribution) | **0.909** | **0.920** | 0.915 | accuracy 0.967 |
| **Leave-one-program-out** (unseen program) | **0.842** | **0.844** | — | the honest cross-program number |

Pooled 5-fold confusion matrix (operating threshold ≈ 0.48):

|              | predicted sink | predicted non-sink |
|---|--:|--:|
| **actual sink**     | TP = 482 | FN = 42 |
| **actual non-sink** | FP = 48  | TN = 2188 |

Honesty notes:
- The cross-program **LOPO 0.842/0.844** is the number to trust for "apply to a
  brand-new binary."
- The pooled 0.91 is mildly optimistic: some authz labels are derived from
  function-name patterns and name is also a feature (partial circularity). LOPO
  generalizes anyway because "auth"-named functions *are* usually authz sinks.
- Residual errors: FN ≈ authz functions whose verdict/vocabulary lives upstream
  in callers; FP ≈ self-cleanup of own files (`do_cleanup`, pidfile/scoreboard).

Example inference (doas, threshold 0.48): flags `checkconfig` (policy),
`main` (privilege-drop + exec), `readpassphrase`, `shadowauth` — exactly its
attack endpoints.

---

## File manifest

```
sink_detector/
├── README.md                  ← this file
├── model/
│   ├── sink_model.json         trained XGBoost model (xgb Booster)
│   ├── feature_spec.json       feature order + name keywords + dwarf-rich/struct cols + threshold
│   └── metrics.json            final metrics (the table above), machine-readable
├── dataset/
│   └── integrated_function_features.csv   labeled dataset: 2760 rows, base features + target_id/function/y
├── data/                       ← bundled so inference/retrain need NO external artifacts
│   ├── all_function_features.csv         EVERY DWARF function x 279 features (what scan_binary reads)
│   ├── dwarf_rich_features.json          source-file/param features (retrain input)
│   └── dwarf_struct_local_features.json  local/struct features (retrain input)
├── feature_extractors/         ALL features below are binary/DWARF-derived (no source)
│   ├── bin_effect_features.py        direct effect-syscall calls per function (call <execve@plt> ...)
│   ├── bin_reach_features.py         call-graph reachability to an effect (transitive, from disassembly)
│   ├── bin_string_features.py        .rodata strings referenced (rip-relative) -> flags + token doc
│   ├── inter_gate_features.py        heuristic "return value branched-on" gating
│   ├── gate_dfg_features.py          DFG-based gating (reaching-defs; optional)
│   ├── dwarf_rich_features.py        DWARF source-file name + param names/types keyword flags
│   ├── dwarf_struct_local_features.py DWARF local-variable names + struct/typedef types (pyelftools)
│   └── callgraph_reach_features.py   shared helpers (program list, dwarf-name loading, paths)
├── train/
│   ├── recall_endpoint_scan.py       label helper: find effect-issuing functions (source allowed here)
│   ├── relabel_all_concrete.py       apply SINK_LABELING_STANDARD -> concrete + authz labels (per binary)
│   ├── build_integrated_dataset.py   assemble feature rows (feats()) + write the dataset CSV
│   ├── gen_all_function_features.py  one-time: dump data/all_function_features.csv (all funcs x 279)
│   └── train_final.py                build 279-feature matrix, train, save model+spec+metrics
├── inference/
│   └── scan_binary.py                scan a target's functions -> ranked sinks
└── docs/
    └── SINK_LABELING_STANDARD.md     the labeling rule (one consistent granularity)
```

### The 279 features (all from the binary's DWARF/disassembly)
| group | count | what |
|---|--:|---|
| base (CFG/disasm) | 125 | instruction/block/edge counts, opcode stats (objdump) |
| binary effect calls | 8 | direct `call <setuid/execve/chmod...@plt>` per category |
| call-graph reachability | 10 | transitively reaches an effect; hop distance; #effect-callees |
| rodata strings | 7 | references path / shell / cred / cap / fmt strings |
| DWARF params | 2 | #params, #pointer-params |
| anti-FP flags | 3 | only-rlimit / dispatcher / effect-but-no-pointer (self-cleanup) |
| heuristic gating | 3 | return-value branched-on by callers |
| **function-name keywords** | 30 | generic security tokens (auth/passwd/verify/access/policy/exec...) |
| **DWARF source-file + param** | ~47 | file is auth.c/privs.c...; param names/types (passwd/uid/cap...) |
| **DWARF locals + struct types** | ~44 | local vars (password/crypt...), struct passwd/sockaddr/cap_t... |

---

## Per-script usage (command · reads · writes)

Two categories:
- **Self-contained (runnable anywhere): `inference/scan_binary.py`,
  `train/train_final.py`.** They use only the bundled `model/`, `data/`, and
  `dataset/`. Verified working standalone.
- **Repo-tied rebuild scripts: everything in `feature_extractors/` plus
  `recall_endpoint_scan` / `relabel_all_concrete` / `build_integrated_dataset` /
  `gen_all_function_features`.** These regenerate features *from the binaries*, so
  they need the 2.7 GB per-target **stage_02 artifact tree** and the original flat
  `scripts/` sibling layout. Run them from the repo `program_targets/scripts/`
  (the copies bundled here are the **identical reference source** — kept so you
  can read exactly how each feature is computed). They take **no arguments** and
  iterate `callgraph_reach_features.py:SRC`, writing one JSON to `ml_dataset/`.

| script | run | reads | writes |
|---|---|---|---|
| `feature_extractors/bin_effect_features.py` | `python3 …/bin_effect_features.py` | per-target `stage_02/.../nginx_disassembly.jsonl` | `ml_dataset/bin_effect_features.json` |
| `feature_extractors/bin_reach_features.py` | `python3 …/bin_reach_features.py` | disassembly + DWARF names | `ml_dataset/bin_reach_features.json` |
| `feature_extractors/bin_string_features.py` | `python3 …/bin_string_features.py` | target ELF `.rodata` + disassembly | `ml_dataset/bin_string_features.json`, `bin_string_tokens.json` |
| `feature_extractors/inter_gate_features.py` | `python3 …/inter_gate_features.py` | disassembly | `ml_dataset/inter_gate_features.json` |
| `feature_extractors/gate_dfg_features.py` | `python3 …/gate_dfg_features.py` | `stage_02/.../nginx_ir_graphs.json` (DFG) | `ml_dataset/gate_dfg_features.json` |
| `feature_extractors/dwarf_rich_features.py` | `python3 …/dwarf_rich_features.py` | `objdump --dwarf=decodedline` + `dwarf_facts.json` | `ml_dataset/dwarf_rich_features.json` |
| `feature_extractors/dwarf_struct_local_features.py` | `python3 …/dwarf_struct_local_features.py` | ELF `.debug_info` (pyelftools) | `ml_dataset/dwarf_struct_local_features.json` |
| `feature_extractors/callgraph_reach_features.py` | (imported, not run directly) | — | shared helpers: program list, DWARF-name loader, paths |
| `train/recall_endpoint_scan.py` | `python3 …/recall_endpoint_scan.py` | program **source** (labels only) + DWARF | scan json under `ml_dataset/program_scans/` |
| `train/relabel_all_concrete.py` | `python3 …/relabel_all_concrete.py` | the feature jsons + DWARF + `SINK_LABELING_STANDARD` | overwrites label column `y` in the dataset CSV |
| `train/build_integrated_dataset.py` | `python3 …/build_integrated_dataset.py` | CFG + all feature jsons (via `feats()`) | `ml_dataset/integrated_function_features.csv` |
| `train/gen_all_function_features.py` | `python3 …/gen_all_function_features.py` | stage_02 CFG/DWARF + feature jsons | **`data/all_function_features.csv`** |
| `train/train_final.py` | `python3 …/train_final.py` | dataset CSV + `data/` dwarf-rich/struct jsons | `model/sink_model.json`, `feature_spec.json`, `metrics.json` |
| `inference/scan_binary.py` | `python3 …/scan_binary.py <target_id> [thr]` | **only** `model/` + `data/all_function_features.csv` | prints ranked sink functions to stdout |

Two run paths:
- **Use the shipped model (self-contained):** needs only `model/` + `data/` — no
  stage_02 artifacts, no `build_curated`. This covers inference and retraining.
- **Rebuild from raw binaries:** stage_02 artifacts → `feature_extractors/*` →
  `train/relabel_all_concrete` → `build_integrated_dataset` →
  `gen_all_function_features` → `train_final`. Needs the per-target stage_02
  artifacts (the repo `scripts/`-copied `build_curated…py`/`generate_curated…py`
  are bundled under `train/` for this path).

## How to run (quick commands)

Dependencies: `python3`, `xgboost`, `scikit-learn`, `numpy` (and `pyelftools`,
`objdump`/`readelf` only for the rebuild-from-binaries path).

### A. Inference — scan a binary (self-contained, the common case)
```bash
python3 inference/scan_binary.py --list          # show targets in the bundled table
python3 inference/scan_binary.py doas_6_8_2       # scan one, default threshold
python3 inference/scan_binary.py doas_6_8_2 0.6   # custom threshold
```
Reads `model/` + `data/all_function_features.csv` only — no external artifacts.
Prints every function scored ≥ threshold, highest first.

### A2. Scanning a brand-new binary (not in the bundled table)
Build it with `-g`, run the DFB `run_step_02_static_ir_cfg.py` to make its
stage_02 artifacts, add it to `callgraph_reach_features.py:SRC`, rebuild the
feature jsons (step C) and `gen_all_function_features.py`, then scan as in A.

### B & C. Rebuild features + dataset from raw binaries (needs the repo stage_02 tree)
Run the **originals** from the repo `scripts/` dir (the bundled copies are
identical reference source but rely on that flat layout + the 2.7 GB artifacts):
```bash
cd ../scripts                                  # program_targets/scripts/
for s in bin_effect bin_reach bin_string inter_gate dwarf_rich dwarf_struct_local; do
  python3 ${s}_features.py                      # -> ml_dataset/*.json
done
python3 build_integrated_dataset.py            # -> ml_dataset/integrated_function_features.csv
python3 relabel_all_concrete.py                # applies SINK_LABELING_STANDARD (concrete + name/file authz)
# copy the refreshed dataset + jsons back into the bundle:
cp ../ml_dataset/integrated_function_features.csv ../sink_detector/dataset/
cp ../ml_dataset/dwarf_rich_features.json ../ml_dataset/dwarf_struct_local_features.json ../sink_detector/data/
```

### D. Retrain the model (self-contained — uses dataset/ + data/)
```bash
python3 train/train_final.py    # -> model/sink_model.json, feature_spec.json, metrics.json
```
A plain retrain keeps the same `feature_order`, so the shipped
`data/all_function_features.csv` stays valid. Only regenerate the table if you
changed the feature set or added programs (needs the repo stage_02 tree):
```bash
python3 train/gen_all_function_features.py   # -> data/all_function_features.csv
```

---

## What is a "sink" here
See `docs/SINK_LABELING_STANDARD.md`. In short: the **lowest real-logic function
that issues a final security effect** (exec/privilege/capability/file-mutation/
network) **or returns an authorization/policy decision** — not thin syscall
wrappers, not pure dispatchers, not self-cleanup of own files.
```
