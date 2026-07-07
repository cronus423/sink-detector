# Unified Sink Labeling Standard (v1)

Purpose: one consistent rule for labeling attack sinks across **all** programs, so
the function-level dataset transfers cross-program. This supersedes the
granularity ambiguity in `CURATED_ATTACK_SINKS.md` (which labeled some programs at
concrete-syscall level and others at handler/dispatch level — the root cause of
nginx failing to generalize: held-out nginx had no other program teaching
"handler = sink").

A "sink" is a **function**, labeled 1 (sink) or 0 (non-sink). One row per function.

---

## 1. Definition

A **sink = attack ENDPOINT**: a function that **performs or decides a final
security-relevant effect**, where that effect (or its key argument) is reachable
from attacker-controlled input.

It is NOT the attack surface/origin (parsers, path canonicalizers, input
readers), NOT pure plumbing, NOT a function that merely *routes toward* an effect.

## 1a. Scope — this detector marks ENDPOINTS; attacker-reachability is a SEPARATE module

A sink here means **"a point worth attacking"** — an *effect endpoint*: a function
that performs a final security-relevant effect (exec / privilege / capability /
file-mutation / **file-read disclosure** / authz / network). **Whether an attacker
can actually reach it — whether the effect's key argument is truly
attacker-controlled — is OUT OF SCOPE for this detector.** That reachability
question is a separate downstream module. This module only outputs the endpoint
list; the reachability module filters it into actual vulnerabilities.

Consequences of this split (adopted 2026-07-06):

- **Do NOT do backward "attacker-input → argument" taint here.** Backward source
  tracking is unreliable (attacker influence can arrive via overflow, indirect
  memory writes, multi-step parsing that breaks the taint chain). We skip it.
- **Detection is FORWARD-only.** For the file-read-disclosure class, the endpoint
  test is: **file-read content flows to an EXTERNAL output channel** —
  `read/fread/fgets/mmap` content reaches `send/sendto/write-to-socket/
  fwrite-or-printf-to-stdout(client)`, in the same function OR via a struct-field/
  fd carried to another function (cross-function forward value-flow).
- **Two conditions must both hold to mark an endpoint** (avoid false endpoints):
  (1) the output content came from a FILE READ (read→output def-use), not a
  server-generated string; (2) the output goes to an EXTERNAL channel, not a log
  file / stderr.
- **Calibration: over-approximate on the PATH dimension, be precise on the
  ENDPOINT dimension.** A function that serves a *fixed/server-controlled* file
  (template, own cert) is STILL marked (it is a real disclosure endpoint; the
  downstream reachability module decides if the path is attacker-controlled).
  Missing a real endpoint is the costly error. But do NOT mark non-endpoints:
  error/status responders (`_NotFound` 404, FTP `550`), banners, computed
  responses (`Fib`, request-echo `HelloPage`), redirects, or log/stderr writers —
  those output something, but not file content to an external channel.

### Endpoint-detection pipeline (converged 2026-07-06)

```
XGBoost (score)         -> easy endpoints A  (clean-primitive sinks, e.g. calls open())
capability recall       -> candidates B      (reaches a file-read primitive; RECALL net,
                                              NOT XGBoost score — score under-ranks the
                                              wrapper-chain sinks and would drop them)
B \ A                   -> forward taint: file-content -> external channel?  confirm
output = A ∪ confirm(B\A)-> "worth attacking" endpoint list  -> reachability module
```
XGBoost handles the clean-primitive endpoints (open-based read sinks transfer well);
forward cross-function value-flow handles the ones it structurally cannot (fopen /
decoupled struct-buffer / delegated-to-helper: `_ReadStaticFiles`, `handle_retr`,
`xfer_retr`, `send_binary_file`). The capability net must be **reach-level** (transitively
reaches a read primitive), not direct-call-level, or the delegated cases (`handle_retr`
calls `str_open`, not a read primitive directly) slip out before taint runs.

## 2. Effect taxonomy (closed list)

Every sink must map to ≥1 of these effect categories. A function mapping to none
is a non-sink. (Reused from the existing pipeline vocabulary, grouped.)

| Category | Final effect |
| --- | --- |
| `exec` | process execution / code loading: execve, execv*, system, popen, posix_spawn, dlopen |
| `privilege` | identity transition: setuid/setgid/setreuid/setresuid/seteuid/setgroups/initgroups |
| `capability` | confinement/cap: capset, chroot, prctl(KEEPCAPS/SECUREBITS), mount, unshare, setns |
| `file_mutation` | chmod/chown/unlink/rename/link/symlink/mkdir/rmdir/truncate/creat, open-for-write |
| `file_read` | content DISCLOSURE: open-for-read/read/pread/fread/fgets/mmap/sendfile/opendir/readdir of an attacker-influenced path whose CONTENTS flow back to the attacker (static-file serve, FTP RETR, TFTP RRQ, SFTP read). NOT metadata-only reads (stat/access/readlink), NOT own-config/pidfile/key reads, NOT credential reads for an auth decision (that is `authz`). |
| `authz` | authorization/authentication DECISION returning allow/deny on attacker input |
| `network` | endpoint to attacker-influenced address: bind/listen/connect, backend connect |

(Optional, label only if clearly attacker-driven: `data_egress` = writing
attacker-controlled data to a privileged channel. Default: skip.)

## 3. THE GRANULARITY RULE (the key fix — apply to every program identically)

For each effect path, label **exactly one** function: the **lowest-level function
with real logic that issues the effect (or returns the decision), whose
security-relevant argument is reachable from attacker input.**

Decision procedure:

1. Locate the effect site: the syscall/libc primitive call (categories
   exec/privilege/capability/file_mutation/network), OR the point where an
   allow/deny verdict is computed (authz).
2. Take the enclosing function `F`.
3. **If `F` is a thin wrapper** — body is essentially `return prim(args);` (≲5
   statements, just forwards arguments with no validation/derivation/branching)
   — it is *syscall-like*, NOT the sink. Move up to the caller that supplies the
   argument and repeat from step 2.
4. The first function with **real logic** (derives/validates/binds the effect's
   argument, or branches on it) = **the SINK. Label it 1.**
5. **STOP. Do NOT also label its callers** — request handlers, command
   dispatchers, event loops, `*_handler`/`*_phase`/`process_request` functions
   are attack-*paths*, captured by reachability features, **not sinks** (label 0
   or leave unlabeled).
6. authz/authn: the sink is the function that computes & returns the verdict
   (e.g. `sudoers_lookup`, `auth_check`, `command_matches`) — same "real logic,
   not a thin forwarder" level.

### Worked examples (same level across programs)

| Program | Effect | SINK (label 1) | NOT a sink (path/wrapper) |
| --- | --- | --- | --- |
| sudo | exec | `sudo_execve` (binds path/argv/envp → execve) | `sudo_execute` (dispatch) |
| lighttpd | exec | `fdevent_fork_execve` | `mod_cgi_handle_subrequest` (handler) |
| nginx | file serve | `ngx_open_and_stat_file` / concrete open-for-serve | ~~`ngx_http_static_handler`~~ (handler → **re-label to 0/path**) |
| proftpd | file_mutation | `sys_chmod`? NO (thin wrapper) → caller w/ logic | `vsf_sysutil_chmod` thin wrapper |
| any | authz | `auth_check` (returns allow/deny) | `http_request_parse` (surface) |

**nginx re-label note:** nginx's current 68 positives are mostly `ngx_http_*_handler`/
`*_phase`/dispatch functions (handler granularity). Under this standard they move
DOWN to the concrete effect functions they call (open/exec/chmod/auth), matching
lighttpd/thttpd. This is the change that should let nginx transfer.

## 4. Positive inclusion — all must hold

1. Maps to ≥1 effect category (§2).
2. Is the correct granularity per §3 (effect-issuing/deciding, not path, not thin
   wrapper).
3. **Attacker-reachability qualifier:** the effect's key argument (path, command,
   uid, address, credential) is plausibly attacker-influenced. A real effect on a
   **fixed/self-controlled** target is NOT a sink (e.g. unlinking your own pidfile,
   chmod of your own scoreboard, cleanup of own tempdir).
4. Resolves to a function in the binary's DWARF table (feature-extractable).

## 5. Negative (label 0) — explicit

- Attack **surface/origin**: request/command parsers, header/URI parsing, path
  canonicalizers (`realpath`, `de_dotdot`, `expand_symlinks`), input readers.
- **Thin wrappers / syscall-like forwarders** (`vsf_sysutil_*`, `sys_*`, `str_*`
  one-liners) → these become FEATURES (effect-call), never labels.
- **Pure dispatch/routing**: command tables, packet dispatch, event loops, broad
  lifecycle/`*_handler` functions whose own body only routes.
- **Metadata reads**: stat/lstat/fstat/readlink/access-probe.
- Utilities: string/buffer/array/hash/alloc/format/logging/output.
- Self-controlled effects on fixed paths (cleanup, own pidfile/scoreboard/socket).
- Capability **probes** (prctl-detect), resource/hardening tuning (setrlimit
  coredump/nproc, setpriority) — security-adjacent, not attacker-value endpoints.

## 6. Edge cases / tie-breakers

- **Multiple effects in one function** → one row, multi-category; still label once.
- **Static duplicates** (same name in two files) → the definition that issues the
  effect; if both, the one in the analyzed binary's DWARF.
- **Macro-expanded effects** → label the C function that textually contains the
  effect/decision.
- **Wrapper chains > 1 hop** of thin forwarders → keep walking up past all thin
  forwarders to the first real-logic function.
- **Unsure between two adjacent levels** → pick the one that *derives/binds the
  attacker-controlled argument*; if still tied, the lower (closer to the effect).

## 7. How to apply (re-labeling workflow)

1. Run `scripts/recall_endpoint_scan.py` → effect-issuing functions per program.
2. For each candidate, apply §3 (thin-wrapper walk) + §4 (attacker-reachability)
   + §5 (exclusions) → verdict, recorded with a one-line reason.
3. **Re-label existing programs to this granularity** (nginx is the big one:
   demote handler labels, promote the concrete effect functions they reach).
4. Validate: every label resolves in DWARF; spot-check that the *same effect*
   is labeled at the *same level* across ≥2 programs (e.g. file-serve open in
   nginx vs lighttpd).

## 8. Why this fixes generalization

Consistent granularity means every test program's sinks have analogues at the
same level in the training programs (e.g. all "open-for-serve" labeled at the
concrete-open level). The earlier failure (nginx 0.04) was not a feature problem
— it was that nginx's handler-level labels had no counterpart in other programs.
