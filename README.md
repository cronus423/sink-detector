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

Model: a single **XGBoost** gradient-boosted-tree classifier, **283 binary
features**, trained on **2798 functions (524 sinks / 2274 non-sinks)** across
16 programs (HTTP, FTP, SSH, sudo/doas/polkit, DNS). Labels cleaned by a
source-verified FP/FN audit (34 corrections — see `FP_FN_AUDIT.md` /
`gt_corrections.json`); the sudoers.so plugin (424 funcs) is fully included.

| Evaluation | Precision | Recall | F1 | Notes |
|---|--:|--:|--:|---|
| **Pooled 5-fold CV** (within-distribution) | **0.907** | **0.908** | 0.908 | accuracy 0.965 |
| **LOPO — XGBoost alone** (unseen program) | **0.923** | **0.782** | 0.847 | honest cross-program |
| **LOPO — full chain (XGBoost + P1–P5)** | **0.923** | **0.803** | 0.859 | + file-read recall booster |

Pooled 5-fold confusion matrix (operating threshold 0.385):

|              | predicted sink | predicted non-sink |
|---|--:|--:|
| **actual sink**     | TP = 476 | FN = 48 |
| **actual non-sink** | FP = 49  | TN = 2225 |

Honesty notes:
- **LOPO** is the number to trust for a brand-new binary. Full-chain LOPO
  (`0.923/0.803`) beats XGBoost alone (`0.923/0.782`): the `endpoint_detector`
  (P1–P5) recovers **+11 file-read / delegation sinks XGBoost structurally misses,
  at +1 FP** (LOPO confusion — XGB alone TP=410 FP=34 FN=114; full chain TP=421 FP=35 FN=103).
- sudo's LOPO recall is low on purpose-honest grounds: 94 sudoers-plugin sinks
  (policy/alias/permission parsing) are hard to transfer cross-program. Earlier
  numbers omitted the plugin; this is the complete, honest evaluation.
- Residual FN ≈ authz functions whose vocabulary lives upstream in callers;
  FP ≈ self-cleanup of own files.

## The integrated pipeline (XGBoost + endpoint_detector)

XGBoost is a high-precision coarse screen for the **broad** sink class
(privilege/exec/file-mutation/authz). It structurally cannot find **file-read
disclosure** endpoints (read a file → send to client) because that needs
whole-program read→socket flow, not a per-function feature. `endpoint_detector/`
(P1–P5, pure static) is the recall booster for exactly that class. `pipeline.py`
chains them as designed:

```
final_sinks = S_xgb  ∪  { P2-P5 endpoints  ∩  (P1 recall_B − S_xgb) }
```

i.e. XGBoost coarse-screens → P1 builds the file-read candidate set → subtract
what XGBoost already found → P2–P5 discriminate the remainder → union. On the
file-read GT the chain reaches **15/15** (vs XGBoost's 11/15). See
`endpoint_detector/README.md` for the P1–P5 / P4 fd-delegation details.

Run:
```bash
python3 inference/scan_binary.py <target>     # XGBoost alone
python3 pipeline.py [target ...]              # integrated chain
```

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
│   └── integrated_function_features.csv   labeled dataset: 2798 rows, base features + target_id/function/y
├── data/                       ← bundled so inference/retrain need NO external artifacts
│   ├── all_function_features.csv         EVERY DWARF function x 283 features (what scan_binary reads)
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
│   ├── gen_all_function_features.py  one-time: dump data/all_function_features.csv (all funcs x 283)
│   └── train_final.py                build 283-feature matrix, train, save model+spec+metrics
├── inference/
│   └── scan_binary.py                scan a target's functions -> ranked sinks
├── endpoint_detector/          file-read-disclosure recall booster (P1-P5, static, no model)
│   ├── detector.py                 P1 recall + P2/P3/P5 taint + P4 fd-delegation (arg/table/queue)
│   └── README.md                   pipeline stages + fd-carrier details
├── pipeline.py                  integrated driver: XGBoost coarse-screen -> P1-P5 -> union
├── FP_FN_AUDIT.md              source-verified FP/FN classification (true error vs GT mistake)
├── gt_corrections.json         the 34 verified label corrections applied before retrain
├── WORKLOG.md                  session log (P4, integration, sudo fix, retrain)
└── docs/
    └── SINK_LABELING_STANDARD.md     the labeling rule (one consistent granularity)
```

### The 283 features (all from the binary's DWARF/disassembly)
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
