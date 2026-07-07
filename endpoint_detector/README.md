# File-read-disclosure ENDPOINT detector (static, no API)

Detects **file-read disclosure endpoints**: a function where file-read content reaches
an **external** output channel (socket / client stdout). This is the class the XGBoost
feature model structurally cannot find cross-program (see `memory/file-read-sink-work.md`
for why — whole-program read→socket taint is heavier than a per-function feature).

Scope reminder (`docs/SINK_LABELING_STANDARD.md` §1a): sink = **effect endpoint**
("a point worth attacking"). **Attacker-reachability is a SEPARATE downstream module**;
this detector only marks endpoints. Detection is **forward-only** (file content →
external channel), never backward attacker-input → argument.

## Run

```bash
python3 endpoint_detector/detector.py [prog ...]      # defaults to all 12 in the GT dict
```

Input = DFB stage_02 artifacts only (binary + DWARF, no C source):
`dfb_attack_feasibility_rethink/program_targets/<prog>/artifacts/stage_02_static_ir_cfg/`
(`nginx_disassembly.jsonl` + `dwarf_facts.json`).

## Pipeline

| Stage | What it does |
| --- | --- |
| **P1** `recall_B` | bounded (≤3) reverse-BFS on the internal call graph → candidate set B (functions that transitively reach a read primitive). Reach-level, not direct-call. |
| **P2** `p2_samefunc` | order-independent intra-proc stack-slot taint: file-read dest slot → (copy-prop) → **external** output use, same function. Order-independent so the `while((n=fread)>0) fwrite` loop layout (output textually before read) still resolves. |
| **P3** `p3_crossfunc` | DWARF send-buffer decomposition: function writes a struct field that is later `send()`/`sendto()` elsewhere, with a real file read nearby. Catches decoupled `_ReadStaticFiles`. |
| **P4a** `p4_fd_delegation` (arg) | traces the **fd value** returned by an `open`-family primitive (or a thin open-wrapper) across a call boundary: the fd is passed as a **register argument** into a *transfer helper* (reaches a content-read AND an external-write). Origins are filtered to **read-only** opens (O_RDONLY) so uploads are excluded at the source. Monotonic slot taint → branch/loop-safe. Catches the FTP delegated chain `handle_retr` (→`vsf_ftpdataio_transfer_file`), `retrieve` (→`send_data`), `serve_file`. |
| **P4b** `p4_fd_delegation` (table) | **global handle-table** carrier: a *registrar* (e.g. sftp `handle_new`) stores an open-fd into a global-backed table entry; a *resolver* (`handle_to_fd`) reads it back. Matched by resolving rip-relative globals to absolute addresses (`pc+size+disp`) + entry offset. Marks the opener that fills the table **and** the consumer that drains it into a read + external-write. Catches openssh `process_open` + `process_read`. |
| **P4c** `p4_fd_delegation` (queue) | **queue-egress** for zero-copy / event-loop servers where the send is a **decoupled `sendfile` in the fdevent loop** (no read→write taint exists). Anchors on `sendfile`, learns the struct field it reads its file fd from (the "mount point"), finds the functions that WRITE that field (the chunkqueue-append family), and treats those as egress helpers — then the same P4a flow marks the caller that owns a read-only open and hands the file to an append helper (the request handler, not the sendfile plumbing). This is P3 re-anchored from `send`'s buffer arg to `sendfile`'s in_fd. Catches lighttpd `http_response_send_file` (+ `http_response_static_errdoc`, `http_response_xsendfile2`). Inherits P3's offset-collision imprecision. |
| **P5** `channel_of` | classifies each output fd/stream **external vs local**, so P2 counts only external egress. Drops read-modify-write of a self-`open()`ed file / stderr. |

**Why fd VALUE flow, not call-graph reach:** an `open()`ed fd reused as a read fd is rare and meaningful; "reaches an open somewhere and a read somewhere within K hops" flags `main()`, config parsers, and every dispatcher (measured: 18–77 funcs/program, and *still* misses the delegated targets). P4 keys on the fd value crossing the boundary, which is precise by construction.

## Current results (validated 2026-07-06)

Recovered by P1–P3 (XGBoost couldn't): microhttp `_ReadStaticFiles`, gopher `send_text_file` /
`send_binary_file`, tinyhttpd `cat`, openssh `do_motd` / `do_nologin`.
P5 killed the 3 clear FPs: proftpd `pr_scoreboard_scrub`, wu_ftpd `acl_join` /
`acl_remove` (they read+write their **own** file, not a socket).

**P4 delegated-fd chains (new):** recovers the download idioms P2/P3 structurally miss —
vsftpd `handle_retr` *(fd_arg)*, wu_ftpd `retrieve` *(fd_arg)*, tinyhttpd `serve_file`
*(fd_arg)*, openssh `process_open` + `process_read` *(fd_table)*, lighttpd
`http_response_send_file` *(fd_queue)*. The read-only-open origin filter drops the upload
counterparts (vsftpd `handle_upload_common`, wu_ftpd `store`) at the source; P4b (handle-table)
and P4c (queue) each fire only on their intended target program (no cross-program blowup).
Of the 5 delegated-chain targets originally listed, 4 are now covered (proftpd `xfer_retr` is the
sole holdout — see below).

**Known limitations / TODO**
- P4 arg-passing tier is a **recall tier, not a precise one** (like P1). Five extra hits —
  dnsmasq `one_file` / `read_servers_file` / `rand_init`, openssh `hostkeys_foreach` /
  `load_hostkeys` — are **lower-confidence, not confirmed false positives**: they read an
  own/config/key file whose transfer helper does reach an external channel, but the in-function
  egress is **logging** (file-derived text → `my_syslog` / `sshlog`, verified in `read_file`),
  not a bulk stream of the content to the remote client. Two reasons they are not dismissed:
  (1) endpoint ≠ reachability — whether the read path/length is attacker-controllable (e.g. an
  overflow redirecting the read) is a SEPARATE downstream module's call, per the scope note above;
  (2) by the letter of "file content reaches an external output channel," syslog is such a channel.
  The reach-based transfer-helper test cannot separate "streams file→socket" from "reads file,
  logs a line" — no hop bound `K` works (dnsmasq `read_file` becomes a helper at the same depth as
  vsftpd's real `rwloop`); distinguishing bulk-content egress from incidental logging needs
  interprocedural **content** taint (does content read from *our* fd reach the external write),
  which the current per-instruction substrate does not carry. The fd-table tier (P4b) is precise.
- **`xfer_retr` (proftpd) — out of reach:** both the open (`pr_fsio_open`) and the read
  (`pr_fsio_read` inside `transmit_data`) dispatch through `call <reg>` **vtables**, so neither
  the fd origin nor the read is statically visible. Needs indirect-call resolution.
- **`ngx_open_and_stat_file` (nginx) — out of reach:** the hardest target — it stacks THREE
  independent blockers, verified in the binary:
  1. **fd at offset 0.** `of->fd` (`ngx_open_and_stat_file` stores it via `mov [rbx],ebp`) and
     `ngx_file_t->fd` are both at struct offset 0, and `sendfile`'s in_fd is `[[buf+0x38]+0]`
     (double pointer indirection). Offset 0 is every struct's first field, so P4c's offset-matching
     (which works for lighttpd's distinctive `chunk->0x28`) collides with everything.
  2. **open-file cache indirection.** The opener writes `of->fd`; the fd then travels of →
     `ngx_open_cached_file` → the handler copies `of.fd` into `buf->file->fd`. The opener never
     touches the send mount point (`buf->file` at 0x38 is written by 76 unrelated functions).
  3. **function-pointer output chain.** `ngx_http_output_filter` dispatches via
     `call QWORD PTR [rip+…]` (the `ngx_http_top_body_filter` pointer) and `ngx_linux_sendfile_chain`
     has NO direct callers (reached only through the `send_chain` pointer) — the handler→sendfile
     path is itself vtable-like, same class as proftpd's blocker.
  Catching it needs a real interprocedural points-to + indirect-call-resolution engine (resolve the
  registered filter/`send_chain` pointers, track the `of`/`buf` structs across the cache, type-aware
  field matching) — a different tool class than these heuristic passes. (lighttpd, whose chunk holds
  the fd in a direct `int` field with a statically-visible `sendfile`, IS covered by P4c.)
- Remaining P3 FP: dnsmasq `create_helper` — offset-collision (its "send" is IPC `send_event`,
  not network). Fix: verify the send fd is a network socket + same struct.
- P4c inherits P3's **offset-collision** imprecision: it also flags lighttpd `http_chunk_append_file`
  / `_range` (the generic append API, not a request handler). Low-count, same class as the P3 FP.
- `p2_charloop` (getc/putc) stays **unwired**: direction (download vs upload) is now resolved by
  P4's read-only-open origin filter instead.
