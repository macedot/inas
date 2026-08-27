<h1 align="center">iNAS</h1>

<p align="center"><strong>Turn an iPhone or iPad into a local SMB 3 file share</strong></p>

<p align="center">
  <img src="https://img.shields.io/github/license/macedot/inas?color=blue" alt="License" />
  <img src="https://img.shields.io/badge/iOS-17%2B-000000?logo=apple&logoColor=white" alt="iOS 17+" />
  <img src="https://img.shields.io/badge/SwiftUI-5-F05138?logo=swift&logoColor=white" alt="SwiftUI" />
  <img src="https://img.shields.io/badge/SMB-3-informational" alt="SMB 3" />
  <img src="https://img.shields.io/badge/Xcode-16%2B-147EFB?logo=xcode&logoColor=white" alt="Xcode" />
</p>

---

**iNAS** is a one-button NAS for iPhone and iPad. Tap Start to share folders over local Wi-Fi with SMB 3 (signed and encrypted). Other computers connect with the username and password shown on screen. SMBv1 is not implemented or accepted.

## Features

- **One control** — a single Start/Stop button; status (Start, Connecting, Stop, Stopping) lives on the button
- **Connecting spin** — a ring animates on the button while the share comes up or shuts down
- **Live credentials** — address, user, and password appear only after Start; tap a row to copy. The session card shows the route to the device, not share names
- **Settings gear** — username, password, “new password each Start”, and extra shares live off the home screen
- **Default sign-in** — user `inas`; empty password generates 8 letters + 4 digits on every Start
- **Custom password** — a password you type is stored in Keychain and reused
- **SMB 3 only** — minimum dialect 3.0.2 (prefers 3.1.1); signing and encryption required; NTLMSSP; no guest. After session setup, unsealed PDUs are dropped
- **Default share** — `inas` maps to Files → On My iPhone/iPad → iNAS
- **Extra shares** — up to 8 more named folders (ASCII `[A-Za-z0-9_-]`, 1–63 bytes) picked in Settings, kept as security-scoped bookmarks
- **Discovery** — advertised as **iNAS** via Bonjour `_smb._tcp` (Mac Finder) plus WS-Discovery, LLMNR, and `iNAS.local` (Windows)
- **Port fallback** — bind 445, then 4455 if 445 is unavailable
- **LAN only** — SMB, discovery UDP, and metadata HTTP bind the current Wi-Fi IPv4; a subnet change stops the share

## Quick Start

Open `Inas.xcodeproj` in Xcode 16+, choose your signing Team, then run the **Inas** scheme on a device.

```bash
xcodebuild -project Inas.xcodeproj -scheme Inas \
  -destination 'platform=iOS Simulator,name=iPhone 16' build
```

A real device is best. The simulator can share to the Mac on port 4455.

### Connect from another computer

1. Add files in the Files app: **On My iPhone/iPad → iNAS** (or pick extra folders in Settings)
2. Open iNAS and tap **Start** (allow Local Network if asked)
3. **Mac:** Finder → Network, or Go → Connect to Server → `smb://<ip>` (or `smb://iNAS.local`). Mount `inas` or any extra share name you added
4. **Windows:** paste the **Windows** row from the session card into File Explorer (`\\<ip>` or `\\iNAS.local` on port 445). Then open `\\<ip>\inas` or `\\<ip>\<share>`. Network Neighborhood listing needs Apple’s multicast entitlement (not available on a standard development profile), so Explorer often will not show iNAS under Network even though the share is up

Keep iNAS open while sharing. iOS does not allow a true always-on file server; on iOS 26 the share can continue for a while after you leave the app.

## Configuration

| Setting                    | Default                         | Description                                              |
| -------------------------- | ------------------------------- | -------------------------------------------------------- |
| User                       | `inas`                          | SMB username (Settings)                                  |
| Password                   | generated on Start              | 8 letters + 4 digits unless you set a custom password    |
| New password each Start    | on                              | Off when you type a password; stored in Keychain         |
| Default share              | `inas`                          | App Documents folder                                     |
| Extra shares               | none (up to 8)                  | Name + folder in Settings; names are `[A-Za-z0-9_-]`, 1–63 bytes |
| Port                       | `445`, fallback `4455`          | Shown in the address if not 445                          |
| Protocol                   | SMB 3.0.2+                      | SMB 3.1.1 preferred; v1 never negotiated                 |

## Development

### Prerequisites

- Xcode 16+
- iOS / iPadOS 17+
- Apple Developer Team for device installs

### Local development

```bash
open Inas.xcodeproj
# Select the Inas scheme and an iPhone or iPad, then Run
```

### Testing

```bash
Scripts/test.sh
```

`Scripts/test.sh` applies the vendor patch series (`Scripts/vendor-check.sh`),
fails CI if owned C files drift from clang-format, optionally lints Swift,
then runs `xcodebuild test` on an available iPhone simulator.

Covers password shape, auto vs custom credentials, path sandbox (no `..`
escape, `openat`/`O_NOFOLLOW`), glob matching, per-IP and global auth lockout,
WS-Discovery XML/HTTP helpers and UDP reply budgets, the share-controller
state machine, and a loopback SMB listener on `127.0.0.1:0`: SMB 2.x / 3.0.0
refused, 3.0.2 / 3.1.1 accepted, create/write/read/delete, traversal refusal,
handle exhaustion, write bounds, directory-handle fd leaks, overlong share
names, and plaintext PDUs after a sealed session.

### Bind and lockout

- SMB, WS-Discovery HTTP, and UDP sockets bind the current LAN IPv4 only.
  A Wi-Fi address change stops the share.
- More than 10 failed logons within 60 seconds from one peer locks that
  peer out for 5 minutes.
- More than 100 combined failures within 5 minutes trips a LAN-wide backoff
  (60 s, doubling per re-trigger, cap 15 min). Any successful logon resets it.
- WSD Probe/Resolve and LLMNR replies are rate-limited per peer (5/s, burst 3).

### Vendor libsmb2

`Vendor/libsmb2` is libsmb2 6.1.0 as imported at `fa52e91`, plus the numbered
series in `Vendor/patches/` (`0001`–`0008`). `Scripts/vendor-check.sh` reapplies
those patches to the baseline and requires a byte match on `lib/` and
`include/`. See `Vendor/UPSTREAM`.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│ iPhone / iPad                                            │
│ ┌──────────────────────────────────────────────────────┐ │
│ │ SwiftUI                                              │ │
│ │  Start/Stop button  ·  session card  ·  Settings     │ │
│ │                      ShareController                 │ │
│ └──────────────────────────┬───────────────────────────┘ │
│                            │                             │
│ ┌──────────────────────────▼───────────────────────────┐ │
│ │ SMBServer thread                                     │ │
│ │  libsmb2.framework (dynamic, LGPL 2.1)               │ │
│ │  POSIX shares  ·  NTLM  ·  SMB 3 seal                │ │
│ └──────────────────────────┬───────────────────────────┘ │
│                            │  smb://<lan-ip>/<share>     │
│                            ▼                             │
│              Mac / Windows / Linux on the same Wi-Fi     │
└──────────────────────────────────────────────────────────┘
```

**How it works:**

1. **Start** — bind SMB (445, then 4455) to the LAN IPv4, pin dialect to SMB 3.x, require signing and encryption, advertise via Bonjour, WS-Discovery, LLMNR, and `iNAS.local`
2. **Auth** — NTLMSSP against the username/password for this session (generated or Keychain); failed logons are throttled per IP and globally
3. **Share** — `inas` maps to the app Documents folder; extra shares map by tree id to picked folders. Paths are walked with `openat`/`O_NOFOLLOW` so `..` and symlink swaps cannot leave the root
4. **Stop** — tear down the listener, wipe auto passwords from memory, hide the session card
5. **Background** — screen stays on while sharing; a short grace period after leaving the app; iOS 26 can extend with a continued-processing task

```
Inas/              SwiftUI app, credentials, discovery, SMB wrapper
  SMB/             Filesystem share, throttle, glob, path sandbox
  Services/        Bonjour, WS-Discovery / LLMNR, share store
  UI/              Start/Stop, session card, Settings
InasTests/         Unit and loopback SMB tests
Libsmb2/           Dynamic framework wrapping vendored libsmb2
Vendor/libsmb2     Upstream libsmb2 6.1.0 plus iNAS patches
Vendor/patches     Numbered series 0001–0008
Scripts/           test.sh, vendor-check.sh
```

## Security

- **No SMBv1** — not compiled, advertised, or accepted
- **Encryption required** — SMB 3 seal; clients that cannot encrypt fail the session; unsealed PDUs after session setup are dropped
- **Signing required**
- **No guest / anonymous**
- **Custom passwords in Keychain**; auto passwords exist only in memory while sharing (mlocked, wiped on Stop)
- **Local network only** — listeners bind the Wi-Fi IPv4; no UPnP, WAN, or relay
- **Auth lockout** — more than 10 failed logons / 60 s from one IP → 5-minute block; more than 100 combined failures / 5 min → LAN-wide backoff
- **Path sandbox** — `openat` / `renameat` / `unlinkat` / `fstatat` with `O_NOFOLLOW`
- **libsmb2** is linked as a dynamic framework to stay compatible with LGPL 2.1

## License

iNAS is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Vendored [libsmb2](https://github.com/sahlberg/libsmb2) remains under the [GNU Lesser General Public License v2.1](Vendor/libsmb2/LICENCE-LGPL-2.1.txt) and is linked as a dynamic framework.
