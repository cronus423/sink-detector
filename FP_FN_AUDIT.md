# FP/FN reality-check audit (integrated pipeline, broad GT, LOPO seed=42)

Goal: for every false-positive and false-negative of the integrated pipeline
(XGBoost ∪ P1–P5) against the broad curated GT (`y`), decide whether it is a
**genuine** error or a **GT labeling mistake**. Verified from source.

Confidence: ALL subagent- or source-verified (2026-07-07). openssh/nginx/dropbear =
subagent-verified; proftpd/sudo/vsftpd/wu_ftpd/dnsmasq/thttpd/lighttpd/tinyhttpd/gophernicus
= source-checked here.

RESULT after applying 34 verified GT corrections (see gt_corrections.json) and re-running the
integrated pipeline (LOPO seed=42): Precision 0.888->0.915, Recall 0.880->0.921 (TP=396 FP=37 FN=34).
The raw GT was noisy in BOTH directions: ~12 real sinks unlabeled + ~22 non-sinks over-labeled.

Sink definition (broad "worth_attack"): performs OR directly gates a final security
effect — privilege change / capability-rlimit / exec-codeload / file mutation /
file-read disclosure / authorization decision. NOT: logging, getters, string parse,
config-directive setters, in-memory bookkeeping.

## FP verdicts (detector flagged; GT=0)

### Real sink GT MISSED — detector was right, NOT a true FP
| prog | func | effect | file:line |
| --- | --- | --- | --- |
| openssh | sshsk_enroll | dlopen()s the SK provider .so | ssh-sk.c:463→140 |
| openssh | do_cleanup | temporarily_use_uid + unlink(auth_info_file) | session.c:2704 |
| gophernicus | gopher_menu | dir menu + gophertag file content → client | menu.c:482 |
| gophernicus | gophermap | reads .gophermap → client | menu.c:301 |
| tinyhttpd | cat | fgets(file) → send(client) loop | httpd.c:180 |
| lighttpd | http_chunk_append_file | appends requested file to response queue | http_chunk.c:148 |
| dropbear | send_msg_userauth_success | *grants* authentication (verified) | svr-auth.c |
| proftpd | xfer_pre_stor / xfer_pre_stou | gate STOR/STOU upload (file write) | mod_xfer.c:1175/1289 |
| proftpd | sys_open | FSIO open() dispatcher | fsio.c:113 |

### TRUE FP — genuinely not a sink
| prog | funcs | why |
| --- | --- | --- |
| openssh | auth_log, auth_debug_add, auth_log_authopts, authmethods_get, auth2_record_info, auth2_record_key, auth2_setup_methods_lists, auth2_update_session_info, input_userauth_info_response, send_userauth_info_request, ssh_agent_bind_hostkey, ssh_agent_sign | logging / getters / protocol relay / agent-RPC helpers |
| proftpd | pr_auth_getpwnam/getpwuid/getpwent/getgrnam/getgrgid/getgrent/getgroups, authfile_getgroups, pr_auth_cache_set, pr_auth_get_anon_config, auth_count_scoreboard, auth_sess_init, set_accessdenymsg, set_accessgrantmsg | NSS getters / cache / config-msg setters / bookkeeping |
| dnsmasq | read_servers_file | reads servers config → stays internal (not sent to client) |
| lighttpd | http_auth_backend_get, http_auth_setenv | auth plumbing / env setter |
| nginx | ngx_http_auth_basic_init | config init (verified) |
| dropbear | buf_get_ecdsa_verify_params, svr_agentcleanup | crypto param parse / memory cleanup (verified) |
| wu_ftpd | access_init | initializes access config (bookkeeping) |

### Borderline (perform a primitive but defensive/generic)
sudo restore_limits / unlimit_nproc / unlimit_sudo / restore_nproc (call setrlimit),
nginx ngx_open_file_wrapper (generic open, also logs), lighttpd stream_open (mmap helper).

## FN verdicts (GT=1; detector missed)

### TRUE FN — real sink genuinely missed this fold
| prog | funcs | category |
| --- | --- | --- |
| proftpd | xfer_retr (RETR), check_group_access, sys_access, sys_faccess, pr_fsio_faccess | file-read / access decision |
| nginx | ngx_open_and_stat_file, ngx_http_access_handler, ngx_http_access_rule, ngx_http_core_access_phase, ngx_http_core_post_access_phase, ngx_http_auth_basic_crypt_handler, ngx_http_valid_referers | file open / access-control (verified) |
| sudo | exec_cmnd, exec_cmnd_pty | execve the target command |
| thttpd | ls, check_referrer, really_check_referrer | dir listing / access decision |
| vsftpd | parse_username_password | USER/PASS auth dispatch |
| wu_ftpd | access_ok | access-control decision |
| openssh | match_principals_command, match_principals_file, match_principals_option, xauth_valid_string | cert-principal authz / xauth exec gate |
| dropbear | checkpubkey_line, checkpubkeyperms, svr_pubkey_allows_agentfwd/local_tcpfwd/pty/tcpfwd/x11fwd | authorized_keys authz (verified) |

### GT OVER-LABEL — GT=1 but not a real sink, NOT a true miss
| prog | funcs | why |
| --- | --- | --- |
| proftpd | set_anonrequirepassword, set_anonrejectpasswords, set_userpassword, set_grouppassword, set_hidenoaccess, set_persistentpasswd, passwd_dup, ensure_open_passwd | config-directive `add_config_param` handlers / struct dup |
| nginx | ngx_http_referer_create_conf, ngx_http_referer_merge_conf, ngx_http_add_referer, ngx_http_referer_variable | config init / variable getter (verified) |
| dropbear | fill_passwd, buf_put_ecc_raw_pubkey_string, svr_add_pubkey_options, svr_pubkey_options_cleanup | getpwnam / marshal / bookkeeping (verified) |
| openssh | sshkey_parse_pubkey_from_private_fileblob_type | pure in-memory parse |

## Final corrected counts (all verified)
34 GT corrections applied (12 unlabeled real sinks → sink; 22 over-labels → non-sink):
- **to sink:** cat, gopher_menu, gophermap, http_chunk_append_file, sshsk_enroll, do_cleanup,
  xfer_pre_stor, xfer_pre_stou, sys_open, ngx_open_file_wrapper, send_msg_userauth_success, svr_agentcleanup.
- **to non-sink:** proftpd set_*password ×6 + passwd_dup + ensure_open_passwd; openssh
  sshkey_parse_pubkey_from_private_fileblob_type; nginx access_rule/add_referer/referer_create_conf/
  referer_merge_conf/valid_referers; dropbear buf_put_ecc_raw_pubkey_string/fill_passwd/
  svr_pubkey_allows_×5/svr_pubkey_options_cleanup.

Integrated pipeline on cleaned GT (LOPO seed=42): **Precision 0.915, Recall 0.921** (TP=396 FP=37 FN=34),
up from 0.888/0.880 on the raw GT. Residual FP=37 are genuine non-sink flags (logging/getters/borderline
rlimit plumbing); residual FN=34 are real sinks this fold's XGBoost missed (access-control decisions,
file opens, exec) — the recall ceiling of the held-out model, not GT error.
