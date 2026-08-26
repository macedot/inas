# iNAS

Turn an iPhone or iPad into a small local NAS. One Start/Stop control shares the app’s Documents folder over **SMB 3** (signed and encrypted). SMBv1 is not implemented or accepted.

Other computers on the same Wi-Fi connect with the username and password shown in the app.

## Requirements

- Xcode 16+
- iOS / iPadOS 17+
- A real device is best (the simulator can share to the Mac on port 4455)

## Build

Open `Inas.xcodeproj`, choose your Team for signing, then run the **Inas** scheme.

```bash
xcodebuild -project Inas.xcodeproj -scheme Inas -destination 'platform=iOS Simulator,name=iPhone 16' build
```

## Use

1. Add files with the Files app: **On My iPhone/iPad → iNAS**.
2. Open iNAS and tap **Start**.
3. From a Mac: Finder → Go → Connect to Server → `smb://<ip>/inas`
4. From Windows: `\\<ip>\inas` (or `\\<ip>@4455\inas` if port 445 is not used)

Default user is `inas`. If you leave the password empty, iNAS generates 8 letters + 4 digits on every Start. A password you type is stored in Keychain and reused.

Keep iNAS open while sharing. iOS does not allow a true always-on file server; on iOS 26 the share can continue for a while after you leave the app via a continued-processing task.

## Protocol

- Minimum dialect: SMB 3.0.2 (prefers 3.1.1)
- Signing required
- SMB3 encryption required
- NTLMSSP auth, no guest
- libsmb2 is linked as a dynamic framework (LGPL 2.1)

## Layout

```
Inas/           SwiftUI app, credentials, SMB wrapper
InasTests/      Password, path sandbox, dialect tests
Libsmb2/        Dynamic framework wrapping vendored libsmb2
Vendor/libsmb2  Upstream libsmb2 sources
```
