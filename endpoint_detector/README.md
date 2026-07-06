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
| **P5** `channel_of` | classifies each output fd/stream **external vs local**, so P2 counts only external egress. Drops read-modify-write of a self-`open()`ed file / stderr. |

## Current results (validated 2026-07-06)

Recovered (XGBoost couldn't): microhttp `_ReadStaticFiles`, gopher `send_text_file` /
`send_binary_file`, tinyhttpd `cat`, openssh `do_motd` / `do_nologin`.
P5 killed the 3 clear FPs: proftpd `pr_scoreboard_scrub`, wu_ftpd `acl_join` /
`acl_remove` (they read+write their **own** file, not a socket).

**Known limitations / TODO**
- `p2_charloop` (getc/putc) is written but **NOT wired**: can't tell download from
  upload within one function (both streams are passed-in `FILE*`s) — needs P4.
- Remaining FP: dnsmasq `create_helper` — P3 offset-collision (its "send" is IPC
  `send_event`, not network). Fix: verify the send fd is a network socket + same struct.
- **P4 (next):** trace an fd from an `open`-family return across arg-passing / globals /
  struct-fields into a helper that does read+external-write. Catches the FTP delegated
  chain (`handle_retr`/`xfer_retr`/`retrieve`), openssh `process_read`, lighttpd
  `http_response_send_file`.
