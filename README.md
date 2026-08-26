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

**iNAS** is a one-button NAS for iPhone and iPad. Tap Start to share the app’s Documents folder over the local Wi-Fi with SMB 3 (signed and encrypted). Other computers connect with the username and password shown on screen. SMBv1 is not implemented or accepted.

## Features

- **One control** — a single Start/Stop button; status (Start, Connecting, Stop, Stopping) lives on the button
- **Connecting spin** — a ring animates on the button while the share comes up or shuts down
- **Live credentials** — address, user, and password appear only after Start; tap a row to copy
- **Settings gear** — username, password, and “new password each Start” live off the home screen
- **Default sign-in** — user `inas`; empty password generates 8 letters + 4 digits on every Start
- **Custom password** — a password you type is stored in Keychain and reused
- **SMB 3 only** — minimum dialect 3.0.2 (prefers 3.1.1); signing and encryption required; NTLMSSP; no guest
- **Documents share** — files live in Files → On My iPhone/iPad → iNAS
- **Discovery** — advertised as **iNAS** via Bonjour `_smb._tcp` (Mac Finder) plus WS-Discovery, LLMNR, and `iNAS.local` (Windows)
- **Port fallback** — bind 445, then 4455 if 445 is unavailable

## Quick Start

Open `Inas.xcodeproj` in Xcode 16+, choose your signing Team, then run the **Inas** scheme on a device.

```bash
xcodebuild -project Inas.xcodeproj -scheme Inas \
  -destination 'platform=iOS Simulator,name=iPhone 16' build
```

A real device is best. The simulator can share to the Mac on port 4455.

### Connect from another computer

1. Add files in the Files app: **On My iPhone/iPad → iNAS**
2. Open iNAS and tap **Start** (allow Local Network if asked)
3. **Mac:** Finder → Network, or Go → Connect to Server → `smb://<ip>/inas` (or `smb://iNAS.local/inas`)
4. **Windows:** File Explorer address bar → `\\<ip>\inas` (or `\\iNAS.local\inas` on port 445). Copy the Windows path from the session card if Explorer does not list iNAS under Network.

Keep iNAS open while sharing. iOS does not allow a true always-on file server; on iOS 26 the share can continue for a while after you leave the app.

## Configuration

| Setting                    | Default                         | Description                                              |
| -------------------------- | ------------------------------- | -------------------------------------------------------- |
| User                       | `inas`                          | SMB username (Settings)                                  |
| Password                   | generated on Start              | 8 letters + 4 digits unless you set a custom password    |
| New password each Start    | on                              | Off when you type a password; stored in Keychain         |
| Share name                 | `inas`                          | Documents folder of the app                              |
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
xcodebuild -project Inas.xcodeproj -scheme Inas \
  -destination 'platform=iOS Simulator,name=iPhone 16' test
```

Covers password shape, auto vs custom credentials, path sandbox (no `..` escape), and SMB 3-only dialect policy.

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
│ │  POSIX share of Documents  ·  NTLM  ·  SMB 3 seal    │ │
│ └──────────────────────────┬───────────────────────────┘ │
│                            │  smb://<lan-ip>/inas        │
│                            ▼                             │
│              Mac / Windows / Linux on the same Wi-Fi     │
└──────────────────────────────────────────────────────────┘
```

**How it works:**

1. **Start** — bind SMB (445, then 4455), pin dialect to SMB 3.x, require signing and encryption, advertise via Bonjour, WS-Discovery, LLMNR, and `iNAS.local`
2. **Auth** — NTLMSSP against the username/password for this session (generated or Keychain)
3. **Share** — `inas` maps to the app Documents folder; paths are sandboxed so `..` cannot leave the root
4. **Stop** — tear down the listener, drop credentials for auto passwords, hide the session card
5. **Background** — screen stays on while sharing; a short grace period after leaving the app; iOS 26 can extend with a continued-processing task

```
Inas/           SwiftUI app, credentials, SMB wrapper
InasTests/      Password, path sandbox, dialect tests
Libsmb2/        Dynamic framework wrapping vendored libsmb2
Vendor/libsmb2  Upstream libsmb2 sources
```

## Security

- **No SMBv1** — not compiled, advertised, or accepted
- **Encryption required** — SMB 3 seal; clients that cannot encrypt fail the session
- **Signing required**
- **No guest / anonymous**
- **Custom passwords in Keychain**; auto passwords exist only in memory while sharing
- **Local network only** — no UPnP, WAN, or relay
- **libsmb2** is linked as a dynamic framework to stay compatible with LGPL 2.1

## License

iNAS is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Vendored [libsmb2](https://github.com/sahlberg/libsmb2) remains under the [GNU Lesser General Public License v2.1](Vendor/libsmb2/LICENCE-LGPL-2.1.txt) and is linked as a dynamic framework.
