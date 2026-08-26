# iNAS Remediation Plan

Findings from a full codebase review (security, tests, refactors) plus the
agreed remediation plan.

**Status:** Phases 0–7 are in the tree, plus PLAN-1 addendum (fd-leak,
share-name charset, loopback 3.x session / CRUD / throttle / handle
exhaustion / write bounds). Discovery uses a session object; vendor
patches `0001`–`0007`. clang-format on owned C files is a hard CI check.

Decisions confirmed during planning:

- Vendor changes managed as a **numbered patch series** with a CI apply-check.
- Auth brute-force throttling: **10 failures / 60 s → 5-minute per-peer lockout**.
- `DialectPolicy.swift` is **deleted**; dialect enforcement is verified by a
  wire-level integration test.
- CI via **GitHub Actions** (`xcodebuild test` on an iPhone simulator).

---

## Review findings

### High severity

| # | Finding | Location |
|---|---------|----------|
| H1 | Listener binds all interfaces, not just LAN. SMB listener binds `INADDR_ANY`; WSD/LLMNR fall back to a wildcard bind; metadata HTTP listener accepts from any interface. Cellular/VPN interfaces are exposed, contradicting the README's "Local network only". | `Vendor/libsmb2/lib/socket.c:1536`, `Inas/Services/DiscoveryUDP.c:49-54`, `Inas/Services/WindowsDiscovery.swift` (5357 listener) |
| H2 | No auth-failure throttling. `#if 0` around `smb2_close_context` on logon failure keeps the connection open and re-armed: unlimited online password guessing against custom passwords. | `Vendor/libsmb2/lib/libsmb2.c:4136-4147` |
| H3 | XML injection via reflection of attacker-controlled `MessageID` into `<wsa:RelatesTo>` in SOAP replies (Probe/Resolve matches and HTTP Get response). | `Inas/Services/WindowsDiscovery.swift:166-173, :409` |
| H4 | Remote-triggerable memory leak: `query_directory_cmd` strdups entry names and the success path never frees them; `query_info_cmd` allocates `rep->output_buffer` that nothing frees after the reply encoder copies it (verified: encoders copy into their own buffers; only the read path adopts its buffer with a `free` callback at `smb2-cmd-read.c:213`). | `Inas/SMB/FilesystemShare.c:606, :635`, `Vendor/libsmb2/lib/libsmb2.c:3802` |
| H5 | Exponential glob matching: `match_pattern_r` is backtracking recursion; a pattern like `*a*a*a*…*b` against a 255-char filename (client-uploadable) is O(n^k). Depth cap of 32 does not prevent it. | `Inas/SMB/FilesystemShare.c:484-528` |

### Medium severity

| # | Finding | Location |
|---|---------|----------|
| M1 | Path sandbox TOCTOU: `inas_path_resolve` canonicalizes, then `open_path`/`set_info_cmd` re-open by path; a symlink swapped in between escapes the root. | `Inas/SMB/PathSandbox.c`, `Inas/SMB/FilesystemShare.c` |
| M2 | Dialect policy is decorative: `DialectPolicy.swift` is referenced only by its own test; real enforcement is a hand-patched case in vendored `libsmb2.c:4301-4305`. Refreshing the vendor tree silently re-enables SMB 2.x. | `Inas/SMB/DialectPolicy.swift`, `Vendor/libsmb2/lib/libsmb2.c:4301` |
| M3 | Keychain errors silently swallowed: `SecItemAdd` status ignored; a failed custom-password save silently degrades to generated-password mode. The real vault is never tested (only `MemoryPasswordVault`). | `Inas/Services/CredentialStore.swift:36` |
| M4 | Auto password lingers in `ShareController.credentials` after stop; README claims "auto passwords exist only in memory while sharing". | `Inas/Services/ShareController.swift` |

### Low severity / notes

| # | Finding | Location |
|---|---------|----------|
| L1 | `query_directory_cmd` re-`rewinddir`s and rescans with `enum_index` skip on each call — O(n²), and `readdir` order changes can skip/duplicate entries. | `Inas/SMB/FilesystemShare.c:569-612` |
| L2 | `desired_access` ignored; every open is effectively read/write (`O_RDWR`). | `Inas/SMB/FilesystemShare.c:255-327` |
| L3 | iOS 26 `BGContinuedProcessingTask` expiry only completes the task; never calls `stop(notify:)`, contradicting comments. | `Inas/InasApp.swift:21-23` |
| L4 | `smb2_serve_port` final context drain skips `destruction_event` → stale client count at shutdown (cosmetic; reset on next start). | `Vendor/libsmb2/lib/libsmb2.c:4728` |
| L5 | A Wi-Fi subnet change silently strands a running share (bound sockets die on roam). | `Inas/Services/ShareController.swift` |

### Missing tests

| Gap | Why it matters |
|---|---|
| `FilesystemShare.c` handlers (create/read/write/rename/delete-on-close, handle exhaustion, error mapping) | Largest attack surface, zero tests. |
| `match_pattern` glob incl. pathological patterns | Backs H5. |
| Wire-level dialect enforcement (vendored ANY3 patch) | The only real enforcement is untested. |
| `WindowsDiscovery.httpRequestComplete` / `uuidFromXML` | Pure functions backing the 5357 HTTP server. |
| `SMBServer.start` port fallback 445 → 4455 | Ports hard-coded, not injectable. |
| `ShareController` state machine (start-fail, stop-during-starting, expiry callback) | Everything hard-wired in `init`. |
| Real `KeychainPasswordVault` round-trip + error paths | Backs M3. |
| PathSandbox boundary cases (>1024-char results, UTF-8, trailing separators) | Current tests are good; buffer edges untested. |
| CI / lint | `Scripts/` is empty; tests run locally only. |

### Refactor suggestions

1. Dependency-inject `ShareController` (store, server, bonjour, discovery, background behind protocols; injectable port list).
2. Remove the global `g` from `FilesystemShare.c`; pass state via the `srvr` context; split handle table from handlers.
3. `openat`-based handle operations (dirfd per handle) to eliminate TOCTOU.
4. XML building in `WindowsDiscovery`: escape helpers or `XMLParser`/`XMLDocument`; make templates pure static functions.
5. Single source of truth for dialect policy, consumed by the C server.
6. Replace the scattered `generation == gen` guards in `WindowsDiscovery` with an atomically-torn-down session object (or actor).
7. `CredentialStore.passwordForStart(inout:)` → value semantics.
8. Move Settings' "typing a password makes it custom" rule into the controller.
9. `NetService` → `NWListener` for Bonjour (NetService deprecated).
10. Flatten `SMBServer.start`'s `withCString` pyramid; loop ports in C.

---

## Implementation plan

Execution order: **1 → 2 → 3 → 4 → 5 → 6 → 7** (Phase 6 is independent and
may interleave; Phase 5 depends on Phase 4). Each phase lands with its tests.

### Phase 0 — Vendor patch discipline (prerequisite)

All changes to `Vendor/libsmb2` (existing and new) must be visible and
re-appliable:

- Extract all iNAS-vs-upstream-6.1.0 diffs into `Vendor/patches/*.patch`
  (numbered series; the existing dialect patch at `libsmb2.c:4301` becomes
  `0001-...`).
- `Scripts/vendor-check.sh`: verifies the patch series applies cleanly to a
  pristine pinned upstream libsmb2 6.1.0 tree.
- Every vendor change in later phases is added as a numbered patch.

### Phase 1 — Quick security fixes (no architecture change)

| # | Fix | Files |
|---|---|---|
| 1.1 | XML-escape reflected `MessageID` (`relatesTo`) in Probe/Resolve matches and the HTTP Get response; new `xmlEscaped()` helper; tests for `<>&"'` and injection payloads | `WindowsDiscovery.swift` |
| 1.2 | Replace exponential `match_pattern_r` with an iterative two-pointer glob matcher, O(n·m), exposed as `inas_glob_match()`; tests incl. `*a*a*…*b` vs 255-char name with a time assertion | new `Inas/SMB/GlobMatch.{c,h}`, `FilesystemShare.c` |
| 1.3 | Free handler reply buffers after encode: `output_buffer` + entry names in `smb2_query_directory_request_cb`; `output_buffer` in the query-info callback (vendor patch); verified by allocation-counting test in Phase 4 | `Vendor/libsmb2/lib/libsmb2.c` |
| 1.4 | `PasswordVault.save` throws; propagate to `.failed` state instead of silent degradation to generated passwords | `CredentialStore.swift`, `ShareController.swift` |
| 1.5 | Clear auto password from `credentials` on stop; reset `showPassword` | `ShareController.stop()` |
| 1.6 | Wire `BGContinuedProcessingTask` expiration → `stop(notify: true)`: move registration from `InasApp.init` into `ShareController` (created at launch, so registration timing holds) | `InasApp.swift`, `ShareController.swift`, `BackgroundShareKeeper.swift` |

### Phase 2 — Bind to LAN only (README promise)

- Vendor patch: `struct smb2_server` gains `char bind_ipv4[16]`;
  `smb2_bind_and_listen` binds it (empty = ANY for upstream compat); allow
  port 0 = ephemeral (needed by tests).
- `inas_smb_config` gains `bind_ip`; `SMBServer.start` passes the LAN IP;
  `ShareController` supplies it.
- `DiscoveryUDP.c:49-54`: delete the `INADDR_ANY` bind fallback — fail instead.
- Metadata HTTP listener: `params.requiredLocalEndpoint = <lan-ip>:5357`.
- Interface watchdog: the stats timer checks `lanIPv4()` still equals
  `endpoint.ip`; on change → `stop(notify: true)` (covers L5).

### Phase 3 — Auth hardening

- Re-enable context close after `LOGON_FAILURE` (remove `#if 0` at
  `libsmb2.c:4136`); verify the error reply still flushes before close
  (asserted by the Phase 4 integration test).
- New optional `auth_failed` handler (vendor patch); `FilesystemShare.c`
  implements per-peer throttling via `getpeername(smb2->fd)`:
  **more than 10 failures within 60 s from one peer → `authorize_user`
  rejects that peer for 5 minutes**. Decision helper (ip, count, now) is pure
  and unit-testable; capped LRU table (64 peers).
- Expose `inas_smb_auth_stats()` for tests.

### Phase 4 — C test harness + FilesystemShare refactor

- Vendor patch: `void *opaque` on `struct smb2_server`; `FilesystemShare.c`
  stops using the global `g` (state via `srvr->opaque`); handle-table and
  path-ops split into functions taking state.
- New `InasCoreTests` target (runs in the simulator):
  - Unit tests: glob matcher, throttle decision helper, sandbox edge cases
    (>1024-char results, UTF-8, trailing separators), leak test via a
    counting allocator around `query_directory` / `query_info` + reply encode.
  - **Loopback integration test**: `inas_smb_start` on `127.0.0.1:0` with a
    temp root, driven by the vendored libsmb2 *client*:
    SMB 2.x refused / 3.x accepted (replaces `DialectPolicy`), wrong password
    fails, throttle kicks in, create/write/read/list/rename/delete round-trip,
    wire-level `..` traversal rejected, 257th open fails, oversized write
    rejected.

### Phase 5 — TOCTOU fix (after harness exists)

- Handles store `(dirfd, relative path)`; all operations via
  `openat`/`renameat`/`unlinkat`/`fstatat` with `O_NOFOLLOW`; `PathSandbox`
  returns a dirfd-anchored result instead of an absolute path.
- Regression tests: symlink-swap attempts.

### Phase 6 — Swift refactors + tests

- DI for `ShareController` (protocols for store/server/bonjour/discovery/
  background, injectable port list) → state-machine tests (start-no-WiFi,
  stop-during-starting, expiry, password wipe).
- Extract pure `WSDMessageBuilder` + `HTTPRequestParser` from
  `WindowsDiscovery` → unit tests (incl. injection payloads).
- `passwordForStart` returns a new struct instead of `inout` + save.
- Move Settings' "typing ⇒ custom password" rule into the controller.
- **Delete `DialectPolicy.swift`** and `DialectPolicyTests.swift`; enforcement
  is verified by the wire-level dialect test from Phase 4.
- `NetService` → `NWListener` for Bonjour (low priority); flatten
  `SMBServer.start`'s `withCString` pyramid → C config helper.

### Phase 7 — CI & tooling

- `.github/workflows/ci.yml`: build + `xcodebuild test` (iPhone simulator),
  vendor patch apply-check, swift-format and clang-format (configs added) via
  `Scripts/test.sh`.
- README: update Testing section; document bind scope and throttle policy.

---

## Accepted tradeoffs

- **More vendor patches** = more upstream-merge friction, mitigated by the
  Phase 0 patch series and CI apply-check.
- **IP-bound listener** means a Wi-Fi subnet change now stops the share
  explicitly (with notification) instead of silently breaking.

## Verification

```bash
xcodebuild -project Inas.xcodeproj -scheme Inas \
  -destination 'platform=iOS Simulator,name=iPhone 16' test
Scripts/vendor-check.sh   # after Phase 0
Scripts/test.sh           # after Phase 7
```
