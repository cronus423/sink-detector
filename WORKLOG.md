# WORKLOG — sink-detector

## 2026-07-06/07 — P4 fd-delegation, XGBoost integration, comprehensive eval + GT audit

### P4: cross-function fd-delegation (endpoint_detector/detector.py)
Added P4 to the file-read-disclosure detector — traces the fd VALUE from an open-family
return across a call boundary into a read+external-write helper. Three carriers:
- **P4a `fd_arg`** — open-fd passed as a register arg into a transfer helper. Read-only-open
  origin filter drops uploads. Catches vsftpd `handle_retr`, wu_ftpd `retrieve`, tinyhttpd `serve_file`.
- **P4b `fd_table`** — global handle-table registrar/resolver (rip-globals resolved via pc+size+disp).
  Catches openssh `process_open` + `process_read`. 0-FP across programs.
- **P4c `fd_queue`** — sendfile-anchored: learn the chunk field sendfile reads its in_fd from, find
  the chunkqueue-append family, reuse P4a to mark the caller. Catches lighttpd `http_response_send_file`.
- **Out of reach (documented in README):** proftpd `xfer_retr` (open+read behind `call <reg>` vtables),
  nginx `ngx_open_and_stat_file` (open-file cache + double indirection + function-pointer filter chain).

### Integrated pipeline driver (pipeline.py)
Chains the two detectors as designed: XGBoost coarse-screen → P1 recall candidates → subtract
what XGBoost found → P2-P5 discriminate the remainder → union. `final = S_xgb ∪ (P2-P5 ∩ (B − S_xgb))`.
Integrated file-read recall = 15/15; P1-P5 recovers the 4 XGBoost missed/couldn't-score.

### Feature extraction for tinyhttpd + gophernicus
They were n/a in XGBoost (missing callgraph_reach/inter_gate/gate_dfg/authz_callee features).
Ran the 4 extractors (existing programs byte-unchanged), appended 67 rows to data/all_function_features.csv.
XGBoost now covers all 16 programs; confirmed it flags the exec/CGI sinks but MISSES the file-read
serving functions (serve_file, send_text/binary_file) — the recall gap P1-P5 fills.

### Comprehensive evaluation (broad GT, LOPO, 16 programs)
Integrated pipeline vs broad curated GT (`y`), honest leave-one-program-out:
raw GT → Precision 0.888, Recall 0.880 (TP=387 FP=49 FN=53).

### FP/FN reality-check audit → GT corrections
Source/subagent-verified every FP and FN (FP_FN_AUDIT.md). GT was noisy BOTH ways: ~12 real sinks
unlabeled, ~22 non-sinks over-labeled. Applied 34 verified corrections (gt_corrections.json):
- to sink: cat, gopher_menu, gophermap, http_chunk_append_file, sshsk_enroll, do_cleanup,
  xfer_pre_stor/stou, sys_open, ngx_open_file_wrapper, send_msg_userauth_success, svr_agentcleanup.
- to non-sink: proftpd set_*password ×6 + passwd_dup + ensure_open_passwd; openssh sshkey_parse...;
  nginx access_rule/add_referer/referer_{create,merge}_conf/valid_referers; dropbear
  buf_put_ecc_raw_pubkey_string/fill_passwd/svr_pubkey_allows_×5/svr_pubkey_options_cleanup.

Cleaned-GT re-run: **Precision 0.915, Recall 0.921** (TP=396 FP=37 FN=34). Residual FP/FN are genuine.

### sudo plugin feature completion + model RETRAIN
The training set was missing 424 sudo functions (the `sudoers.so` plugin). Not a bug: the plugin
was already built + statically analyzed (`stage_02_sudoers_plugin/`, Jun 19) — no rebuild/VM/local-sudo
touched. The 424 were in the labels but absent from the 283-feature inference table because
`dwarf_rich`/`struct_local`/`callgraph_reach` filter to the main binary's DWARF (160 funcs).
Fix: reused the 156 I.feats columns from `integrated` (already correct via build_curated's aux lookup),
recomputed `name_*` from names, and computed `dwarf_rich`+`struct_local` on `target/sudoers.so`
(objdump decodedline + pyelftools). Appended 424 rows → sudo now 584 funcs, 0 broken, median 70/283
nonzero. Trainable set: 2374 -> **2798 functions (534 sinks pre-correction, 524 after)**, matching the
original metrics.

RETRAINED (train_final config: binary:logistic, depth 5, eta 0.05, 300 rounds, subsample 0.85) on the
cleaned 2798-func dataset. Saved model/sink_model.json + feature_spec.json (thr 0.385) + metrics.json.
- pooled 5-fold: P 0.907 / R 0.908 / F1 0.908 (was 0.895).
- cross-program LOPO (honest): P 0.923 / R 0.782 for XGBoost alone; **full chain (XGB + P1-P5): P 0.923 /
  R 0.803 / F1 0.859** — P1-P5 recovers +11 real sinks XGBoost missed at +1 FP. LOPO balanced dipped
  0.818->0.810 only because full sudo now contributes 94 hard-to-transfer plugin sinks (honest, not a regression).
