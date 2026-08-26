# PLAN-1 — Implementation Review Addendum

Follow-up to `PLAN.md` after re-reviewing the codebase that implemented it.
This document records the status of the original plan, the new findings made
while reviewing that implementation, and the addendum work items — including
a second round of vendor bugs found while verifying the addendum (section 4).
**All items below are implemented and verified** (vendor patch series +
`xcodebuild test` green, loopback probes green under ASan/UBSan).

## 1. Status of PLAN.md

| Plan phase | Status |
|---|---|
| 0 — Vendor patch series | Done: `Vendor/patches/0001-0007`, `Vendor/UPSTREAM`, `Scripts/vendor-check.sh` (verified passing against baseline `fa52e91`) |
| 1.1 XML escaping | Done: `WSDMessageBuilder.xmlEscaped` on `RelatesTo` + injection tests |
| 1.2 Iterative glob | Done: `GlobMatch.c` O(n·m) + pathological-pattern timing test |
| 1.3 Reply-buffer leaks | Done: vendor frees `output_buffer` (query-dir + query-info); entry names freed |
| 1.4 Keychain errors | Done: `save` throws; surfaced as `.failed`; real-vault roundtrip test |
| 1.5 Auto-password wipe on stop | Done: `finishStop` + test |
| 1.6 BGTask expiry → stop | Done: registration moved into `ShareController` |
| 2 — LAN-only bind | Done: `bind_ipv4`, `smb2_bind_and_listen_ip`, port 0, UDP wildcard fallback removed, `requiredLocalEndpoint`, interface watchdog |
| 3 — Auth hardening | Done: flush-then-close on logon failure, `auth_failed` handler, `AuthThrottle` (10/60 s → 5 min, LRU 64), `inas_smb_auth_stats` |
| 4 — C harness + loopback tests | Done (was partial; closed by A3/A4 below) |
| 5 — TOCTOU | Done: `inas_path_resolve_at`, dirfd+leaf handles, `renameat`/`unlinkat`, symlink-swap test |
| 6 — Swift refactors | Done: DI protocols, controller state tests, extracted builders, value-type `passwordForStart`, `DialectPolicy.swift` deleted |
| 7 — CI | Done: `ci.yml`, `Scripts/test.sh`, format configs (advisory) |

Beyond the plan, the implementation added **multi-share support** (up to 9
shares, security-scoped bookmarks, per-tree rootfd), and fixed former notes
L1 (enum rescan), L2 (desired_access → open flags), L4 (destruction events on
shutdown drain).

## 2. Findings from the implementation review (all fixed)

| # | Finding | Severity |
|---|---|---|
| N1 | **fd leak on every directory handle close** — `handle_free` did `closedir(h->dir); h->fd = -1;`, but every `fdopendir` site passes a `dup()`, so `closedir` never owns `h->fd`; the original fd was discarded open. | High |
| N2 | **Share-name validation characters vs bytes** — `ShareName.isLegal` allowed 1–64 Swift `Character`s incl. all Unicode alphanumerics, but C stores `char name[64]` and fails `inas_smb_start` with `ENAMETOOLONG` (mapped to the misleading "Could not open an SMB port"). | Medium |
| N3 | **Dead test helpers** — `inas_smb_client_roundtrip` and `inas_smb_auth_stats` compiled but unused by any test; handle exhaustion, oversized write, accepted dialects untested. | Medium |
| N4 | **SMB client probe code shipped in release app target** — `SMBClientProbe.c` is SMB *client* code with no production caller. | Low |
| N5 | Minor: no `BonjourAdvertiser.deinit` stop; legacy `inas_path_resolve`/`PathSandbox.swift` are test-only but unmarked; tree-id trust undocumented. | Low |

## 3. Addendum items (implemented)

### A1 — Fix the `handle_free` fd leak

`handle_free` no longer discards `h->fd` when a `DIR *` exists; `closedir`
releases only the dup'd descriptor it owns, and the remaining descriptors are
closed by the existing branches. Regression test: `inas_smb_client_dir_cycle`
drives 300 open/close directory iterations over one connection;
`testDirectoryCyclesDoNotLeakServerFDs` counts process fds via `/dev/fd`
before/after and requires the delta to stay bounded.

### A2 — Share-name validation, Swift and C

- `ShareName.isLegal`: ASCII `[A-Za-z0-9_-]` only, 1–63 **bytes**
  (`utf8.count`), matching C's `char name[64]` with NUL.
- Defense in depth: `inas_smb_start` validates the same charset/length via
  `valid_share_name()` and returns `-EINVAL` (loopback-tested, incl.
  multi-byte names).
- `SMBServer.start` maps `-EINVAL`/`-ENAMETOOLONG` to `invalidConfig`
  ("Username, password, and share names must be valid.").

### A3 — Wire the existing probes and close the Phase-4 gaps

`SMBLoopbackTests` now covers, via the vendored libsmb2 client on
`127.0.0.1:0`:

- full file-op roundtrip + wire-level `..` traversal refusal
  (`inas_smb_client_roundtrip`)
- dialect **acceptance**: 3.0.2 and 3.1.1 negotiate with the expected revision
- throttle: 11 wrong-password logons lock the peer
  (`inas_smb_auth_stats`: 1 peer, 1 locked; correct password then also fails)
- handle exhaustion: 257 concurrent opens → exactly 256 succeed
  (`inas_smb_client_open_many`)
- write bounds: exactly `max_write_size` (1 MiB) succeeds, a single raw WRITE
  of 1 MiB + 1 is rejected (`inas_smb_client_write_bounds`; the sync client
  also pre-validates against the negotiated maximum, so this asserts the
  end-to-end contract)
- fd-leak regression (A1) via `inas_smb_client_dir_cycle`
- illegal share names rejected with `-EINVAL` (A2)

### A4 — Keep client probe code out of release builds

`SMBClientProbe.c` implementations are wrapped in `#if DEBUG`. Test action
builds Debug, so tests keep the symbols; release archives drop the client
code.

### A5 — Minor cleanups

- `BonjourAdvertiser.deinit { stop() }`
- `PathSandbox.h`: `inas_path_resolve` marked legacy/test-only; the server
  path uses `inas_path_resolve_at` exclusively
- comment on tree-id trust at `share_rootfd_for_tree`
- `.swift-format` v1 config verified against the toolchain's `swift format`
  (accepted; lint is advisory in `Scripts/test.sh`)

## 4. Second-round vendor bugs (found while verifying A3, fixed in patch 0007)

The new loopback tests could not pass against a *sealing* server: every
positive connection (3.0.2 and 3.1.1) failed during session setup. Root-caused
with a native macOS repro harness (server + client linked into one binary,
ASan/UBSan clean) and fixed as
`Vendor/patches/0007-preauth-hash-server-seal-keys-and-compound-fid.patch`:

| # | Bug | Fix |
|---|---|---|
| V1 | **Signing disabled under seal broke session setup.** The server set `smb2->sign = 0` during negotiate when sealing was on, so (a) the final session-setup response was unsigned — rejected by any client enforcing MS-SMB2 3.2.5.3.1 (macOS/Windows with signing required, and this fork's own hardened client) — and (b) `smb2_create_signing_key()` early-returned before deriving the *encryption* keys, leaving the server unable to seal or unseal anything. | Server keeps `sign` through session setup; the final response sets `SMB2_SESSION_FLAG_IS_ENCRYPT_DATA` so sealing clients switch over; `sign` is dropped only after the final response is queued. |
| V2 | **Server derived client-perspective seal keys.** `ServerIn/SMBC2SCipherKey` and `ServerOut/SMBS2CCipherKey` are named from the client's view; `smb3-seal.c` always encrypts with `serverin_key`/decrypts with `serverout_key`, so a server context must derive the labels swapped. | `smb2_create_signing_key()` swaps C2S/S2C labels for `smb2_is_server()` contexts. |
| V3 | **Preauth integrity hash computed after the out vectors were consumed.** Both sides hashed replies *after* `smb2_queue_pdu()`, whose opportunistic write consumes the vectors — on fast links the server hashed zero bytes, so SMB 3.1.1 keys diverged. | The hash now happens inside `smb2_queue_pdu()` (after signing, before any write), gated to NEGOTIATE/SESSION_SETUP; `smb3_update_preauth_hash` declared in `smb3-seal.h`. |
| V4 | **Compound placeholder file id unsupported.** Clients (mkdir/rmdir/opendir/set-info via the sync API) chain e.g. CREATE+CLOSE with the all-0xff `compound_file_id` placeholder; the server treated it as a real id → `STATUS_NOT_IMPLEMENTED`. | Server records the CREATE reply's file id per compound (`smb2->compound_fid`), substitutes the placeholder in follow-up commands before dispatch, and clears it when the next PDU starts arriving. |

The repro also surfaced a client-side double-free in `query_cb`'s
decode-failure path (`dir->cb()` then `free_smb2dir()`), reachable only via
the V1–V4 bugs; with those fixed the full probe suite (roundtrip, dir cycles,
handle exhaustion, write bounds, both dialects) passes 10/10 under
ASan+UBSan, and the ownership pattern matches the other error paths in that
file.

## 5. Verification

- `Scripts/vendor-check.sh` — patch series 0001–0007 applies to the
  `fa52e91` baseline and reproduces `Vendor/libsmb2` exactly.
- `Scripts/test.sh` — full `xcodebuild test` (iPhone simulator, Debug): all
  suites green, including the ten loopback tests.
- Native repro (macOS, ASan+UBSan): all six client probes pass repeatedly —
  `open_many(257)=256`, `roundtrip=0`, `dir_cycle(300)=0`,
  `write_bounds=0`, `connect302=0`, `connect311=0`.
