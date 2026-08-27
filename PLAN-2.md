# PLAN-2 — Second-Addendum Review & Execution Plan

Follow-up to `PLAN.md` (original plan) and `PLAN-1.md` (first addendum + the four
second-round vendor bugs V1–V4), this round re-reviews the codebase **after**
those fixes landed (HEAD `9f69569`).

This is the **execution-ready** version — the review findings are locked,
decisions are made, and the file-by-file change list is concrete. Three
corrections to the original draft are folded in (see §2).

**Status:** All six phases are implemented. Vendor patch series is
`0001`–`0008`; loopback, throttle, and ReplyBudget tests cover the new
behavior.

Status verified before this round:

- Vendor patch series 0001–0007: `Scripts/vendor-check.sh` passes.
- `Scripts/test.sh` (`xcodebuild test`): all suites green, incl. loopback.
- Native macOS ASan+UBSan repro: all six probes pass.

## 1. New findings (current code)

### H1 — Auth throttle does not stop distributed brute force
**File:** `Inas/SMB/FilesystemShare.c:257-282`, `Inas/SMB/AuthThrottle.c`

The throttle is keyed by `peer_ipv4` (64-slot LRU). A distributed brute
force across multiple LAN IPs evades the per-IP lockout. There is no
secondary or global counter.

(Sub-claim from the draft — "wipe `smb2->password` after
`authorize_user`" — is mostly moot: the vendor already wipes it at
`Vendor/libsmb2/lib/ntlmssp.c:1344-1345` immediately after `NTOWFv2`.
Residual: early-error paths before line 1345 leave it set until context
close, but those connections are torn down anyway.)

### H2 — Plaintext password hygiene in a process-global
**File:** `Inas/SMB/FilesystemShare.c` (the `g.password[128]` global),
`Inas/Services/CredentialStore.swift`

`g.password` must live in process memory for the whole Start→Stop
lifetime (the server needs it to derive NTOWFv2 during each handshake).
`inas_smb_start` already zeroes the whole buffer before the `snprintf`
(`FilesystemShare.c:1302`), so old passwords do **not** linger between
Start cycles — but the wipe is a plain `memset` (as is the Stop-time
wipe), which the optimizer is not obligated to keep. There is no
`mlock`, so the buffer can be paged out.

(Sub-claim from the draft — "drop the global entirely into per-connection
buffers" — is infeasible: `authorize_user` needs the plaintext during each
NTLMSSP handshake, so the server must hold the secret for the whole
session. The correct mitigation is hygiene on the storage that must
exist.)

### H3 — WS-Discovery / LLMNR reply to any peer, no rate limit
**File:** `Inas/Services/WindowsDiscovery.swift:177-189, 214-219, 476-497`

`Probe`/`Resolve` (UDP) and LLMNR name queries are answered for any
source on the LAN. No per-peer throttle; an attacker (or a chatty AV
scanner) can keep the dispatch queue busy. Replies carry only the LAN IP
and TCP port (no secret), but the service is an attractive nuisance.
The WSD `Get` metadata responder (TCP 5357) is likewise unthrottled but
is deliberately left out of the fix: each request costs a TCP connection
and the listener is bound to the LAN interface.

### H4 — Server does not enforce inbound encryption on a sealed session
**File:** `Inas/SMB/FilesystemShare.c` (whole); flagged in `PLAN-1.md` §4 as
a follow-up.

A sealed session requires sealed client requests. Today the server
decodes a transform header when present and treats absent header as
plaintext — no check rejects an unsealed PDU after session setup when
`smb2->seal` is set.

### M1 — `share_from_tree_path` truncates silently
**File:** `Inas/SMB/FilesystemShare.c:223-240`

`snprintf(out, out_len, "%s", name)` with `share[128]` and a path up to
~512 UTF-8 bytes truncates silently. Fail-closed downstream (lookup
misses), but worth an explicit reject.

### M2 — Path-sandbox `*at`/`O_NOFOLLOW` invariant not documented in code
**File:** `Inas/SMB/FilesystemShare.c`, `Inas/SMB/PathSandbox.c`

Current code is race-free; a future contributor adding `stat(path)` on a
user-provided absolute path would silently reintroduce TOCTOU. Fix is a
doc comment, not a code change.

### M3 — Domain is ignored; lock granularity is the single `g.lock`
**File:** `Inas/SMB/FilesystemShare.c:260-281, 486-509`

1. Only `DOMAIN\` is stripped from the user; `@REALM` is not. Single-user
   device, intended; document.
2. Every dispatch handler holds `g.lock` across I/O. Serializes the server
   under load. Per-share / finer-grained locks would help but aren't
   urgent given iOS background constraints; document for future profiling.

### M4 — Bonjour TXT hard-coded `path=/inas` (out of scope)
**File:** `Inas/Services/BonjourAdvertiser.swift`

Documented in `PLAN-1.md`. Multi-share discovery isn't in this round.

### L1 — `SMBClientProbe.h` declarations not `#if DEBUG`-gated
**File:** `Inas/SMB/SMBClientProbe.h`

The `.c` is gated; the `.h` is not. Visible everywhere via the bridging
header in Release.

### L2 — Legacy `inas_path_resolve` + `PathSandbox.swift` shipped in Release
**File:** `Inas/SMB/PathSandbox.c`, `Inas/SMB/PathSandbox.swift`

Header is marked legacy/test-only; the implementation is not gated.

### L3 — Deep `withCString` nesting in tests (cosmetic, deferred)
**File:** `InasTests/SMBLoopbackTests.swift:54-86`

### L4 — `BonjourAdvertiser.deinit { stop() }` confirmed safe
**File:** `Inas/Services/BonjourAdvertiser.swift`

### L5 — `setShareFolder` re-creates bookmarks (cosmetic comment)
**File:** `Inas/Services/ShareController.swift`

## 2. Decisions (locked)

1. **Throttle scope (H1):** **per-IP + global backoff**. Global rule:
   >100 combined failures / 5 min → 60 s backoff, doubling per
   re-trigger (cap 15 min). Any success resets it. Tradeoff accepted:
   an attacker can deliberately lock everyone out by spamming failures
   (recoverable: the user is holding the device).
2. **Password memory hygiene (H2):** **mlock + wipe hygiene**. `mlock`
   once at process init; harden the existing pre-overwrite wipe in
   `inas_smb_start` and the stop-time wipe from `memset` to `memset_s`
   (Apple SDKs have no `explicit_bzero`). No `munlock` (the buffer is
   reused across cycles).
3. **Vendor patch 0008 (H4):** **implement with raw-probe test**.
   Server requires transform header after `session_established` fires;
   new `inas_smb_client_plaintext_after_session` probe in `SMBClientProbe.c`
   to drive a plaintext CREATE post-session and assert disconnect.
4. **Phases 4–5 in scope:** discovery token bucket + M/L cleanups all in.

## 3. Execution phases (concrete change list)

| Phase | Files | Tests |
|---|---|---|
| 1 — Patch 0008 (H4) | `Vendor/libsmb2/include/libsmb2-private.h` (+ `session_up` bit); `Vendor/libsmb2/lib/libsmb2.c` (set in `session_established` handler); `Vendor/libsmb2/lib/socket.c` (reject plaintext when sealed+up); `SMBClientProbe.{c,h}` (raw probe); regenerate `Vendor/patches/0008-*.patch` | New `SMBLoopbackTests.testRejectsPlaintextAfterSealedSession`; `vendor-check.sh` reports 8 patches |
| 2 — Throttle (H1) | `AuthThrottle.{c,h}` (global counter + backoff state); `FilesystemShare.c` (`authorize_user` checks global first; `auth_failed`/success update both counters) | `AuthThrottleTests` (global window, doubling, cap, success-reset); loopback lockout extended for the global path |
| 3 — Password hygiene (H2) | `FilesystemShare.c`: `mlock` in `inas_init`; upgrade the wipes in `inas_smb_start` (pre-overwrite) and `inas_smb_stop` from `memset` to `memset_s` | Compile + ASan repro re-run only |
| 4 — Discovery token bucket (H3) | `WindowsDiscovery.swift` (small `ReplyBudget` struct, per-IP tokens 5/s, burst 3, max 32 IPs, pruned on access, consulted in `handleWSD` and `drainLLMNR` — UDP only; the `Get`/5357 HTTP path is intentionally excluded) | Pure-function unit tests: refill, burst, eviction, per-IP isolation |
| 5 — M/L cleanups | `FilesystemShare.c` (M1 `snprintf` truncation reject; M2 invariant comment; M3 doc); `SMBClientProbe.h` (L1 `#if DEBUG`); `PathSandbox.c/.h` + `PathSandbox.swift` (L2 `#if DEBUG`); `ShareController.swift` (L5 comment) | Long-share-name loopback test (M1) |
| 6 — Verification | — | `Scripts/vendor-check.sh` (8 patches); `Scripts/test.sh`; ASan/UBSan repro re-run + new cases; `git status` clean before commit |

### 3.1. Phase 1 detail — vendor patch 0008

`smb2_context` gets `uint8_t session_up:1;` next to `seal:1`/`sign:1` (near
`libsmb2-private.h:226`). `smb2_close_context` clears keys/ids but not the
bitfields, so the patch explicitly adds `smb2->session_up = 0;` there. In
`Vendor/libsmb2/lib/libsmb2.c`, just before
`smb2_cmd_session_setup_reply_async` queues the final success reply
(line ~4327, the `session_established` handler invocation), set
`smb2->session_up = 1`. In `Vendor/libsmb2/lib/socket.c` `SMB2_RECV_HEADER`
(line ~452): when `smb2_is_server(smb2)` && `smb2->seal` && `smb2->session_up`,
if the incoming bytes are not the transform magic **and** `enc_depth == 0`,
set error "unsealed PDU after encrypted session" and `return -1`.
`enc_depth` is required because a decrypted transform is fed back through
the same `SMB2_RECV_HEADER` state; without the guard, a legitimate sealed
PDU is rejected as plaintext after unsealing. `NEGOTIATE` and the initial
`SESSION_SETUP` remain exempt because `session_up` is set only as the final
session-setup reply is queued. Note this deliberately rejects a *second*
plaintext SESSION_SETUP on an already-sealed connection (SMB2 permits
multiple sessions per connection) — acceptable for a single-user appliance,
and it hardens against downgrade.

The raw-API probe in `SMBClientProbe.c` reuses the `raw_cb` /
`wait_for_cb` pattern from `inas_smb_client_write_bounds`. Wire-level
test: connect → negotiate → session-setup handshake → assert plaintext
CREATE via `smb2_cmd_create_async` returns error / context closes.

### 3.2. Phase 2 detail — global throttle

```c
/* AuthThrottle.h additions */
typedef struct inas_auth_global {
    unsigned        fails;
    time_t          window_start;
    time_t          backoff_until;
    unsigned        streak;          /* doubles backoff */
} inas_auth_global;

/* Tunables (header) */
#define INAS_AUTH_GLOBAL_WINDOW_SEC  300
#define INAS_AUTH_GLOBAL_LIMIT       100
#define INAS_AUTH_GLOBAL_BACKOFF_SEC  60
#define INAS_AUTH_GLOBAL_BACKOFF_CAP  900   /* 15 min */

int  inas_auth_global_locked(const inas_auth_global *g, time_t now);
void inas_auth_global_record_failure(inas_auth_global *g, time_t now);
void inas_auth_global_record_success  (inas_auth_global *g);
```

`authorize_user` checks `inas_auth_global_locked` first; if locked, return
`-1` immediately — matching the existing per-IP lockout path
(`FilesystemShare.c:266-268`), which also rejects early. Timing is not
uniform vs. a wrong-password attempt (which runs NTLM against the dummy
password); that is accepted for both lockout paths rather than papered
over. Both counters record on failure; success resets both. Backoff
doubles per re-trigger (cap 15 min) and clears on any success.

### 3.3. Phase 3 detail — password hygiene

In `inas_init` (constructor in `FilesystemShare.c`, ~line 1183):
`mlock(g.password, sizeof g.password);` once.

In `inas_smb_start` (the `snprintf` of `config->password` into `g.password`,
~line 1309, preceded by an existing full-buffer `memset` at ~line 1302):
upgrade that pre-overwrite wipe to `memset_s(g.password, sizeof g.password,
0, sizeof g.password)`. And upgrade the existing `memset` in
`inas_smb_stop` (~line 1417) the same way. (`memset_s`, not
`explicit_bzero`: the Apple SDK has no `explicit_bzero`.)

### 3.4. Phase 4 detail — discovery token bucket

Pure logic, Swift static:

```swift
struct ReplyBudget {
    struct Bucket { var tokens: Double; var lastRefill: Date }
    var table: [String: Bucket] = [:]
    let rate = 5.0, burst = 3.0, maxIPs = 32

    mutating func allow(ip: String, now: Date) -> Bool {
        prune(now: now)
        var b = table[ip] ?? Bucket(tokens: burst, lastRefill: now)
        let elapsed = now.timeIntervalSince(b.lastRefill)
        b.tokens = min(burst, b.tokens + elapsed * rate)
        b.lastRefill = now
        if b.tokens >= 1 { b.tokens -= 1; table[ip] = b; return true }
        table[ip] = b
        return false
    }
}
```

Consulted in `handleWSD` and `drainLLMNR` before building a reply. LLMNR
already runs on the discovery queue; WSD runs on `wsdSource`'s event handler
— both serialize through `queue` so `ReplyBudget` doesn't need its own
lock (mutable on a single queue). Use a private struct on
`WindowsDiscovery` so it doesn't get raced from other callers.

### 3.5. Phase 5 detail — M/L

- `FilesystemShare.c:238`: replace the silent `snprintf` with
  `if (snprintf(...) >= (int)out_len) { free(utf8); return -1; }` and
  add the loopback test that tree-connects to a 200-char share name and
  asserts the tree connect fails with an error reply (the connection
  itself stays up — normal SMB2 behavior for a failed TREE_CONNECT).
- `FilesystemShare.c` top: invariant comment for M2.
- `authorize_user`: M3 doc comment.
- `SMBClientProbe.h`: `#if DEBUG` around declarations.
- `PathSandbox.{c,h}`: `#if DEBUG` around `inas_path_resolve`; same for
  `PathSandbox.swift` (drop the type in Release — tests use it via the
  Debug-compiled app).
- `ShareController.setShareFolder`: L5 comment.

## 4. Test plan per phase

- **Phase 1**: `Scripts/vendor-check.sh` → 8 patches; `Scripts/test.sh` →
  `testRejectsPlaintextAfterSealedSession` green.
- **Phase 2**: `AuthThrottleTests` add: window reset, doubling
  (`streak`), cap (15 min), success reset; loopback `testThrottleLocks...`
  extended to assert global threshold (drive 101 failures).
- **Phase 3**: compile + ASan repro re-run.
- **Phase 4**: `ReplyBudgetTests`: refill, burst, eviction (>32 IPs),
  per-IP isolation, drain behavior.
- **Phase 5**: loopback `testRejectsOverlongShareName` (M1).

## 5. Verification (Phase 6)

1. `Scripts/vendor-check.sh` → **8 patches, ok**
2. `Scripts/test.sh` → full simulator suite green (75 tests), including
   `testRejectsPlaintextAfterSealedSession`, global throttle,
   overlong share name, and `ReplyBudgetTests`.
3. Native ASan/UBSan repro re-run is optional; simulator loopback covers
   the new probe (`plaintext_after_session` waits for hangup rather than
   decoding a transform with sealing disabled on the client context).
4. Manual: Bonjour/WSD still advertise (UDP replies are only rate-limited).
5. Work is uncommitted; commit message should reference PLAN-2.

## 6. Out of scope (explicit)

- Per-share / finer-grained locks (M3 sub-item 2) — deferred until a
  load profile shows `g.lock` is a bottleneck.
- Multi-share Bonjour TXT (M4) — deferred.
- Testing infrastructure changes (H4 test scope is the new raw probe; the
  loopback harness stays as-is).
- Any new vendor patches beyond 0008 — none required by this round.
