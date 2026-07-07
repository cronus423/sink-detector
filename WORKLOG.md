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
