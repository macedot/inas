#!/usr/bin/env bash
# Local / CI verification: vendor patches, unit tests, optional format.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

"$ROOT/Scripts/vendor-check.sh"

C_FORMAT_FILES=(
  Inas/SMB/AuthThrottle.c Inas/SMB/AuthThrottle.h
  Inas/SMB/GlobMatch.c Inas/SMB/GlobMatch.h
  Inas/SMB/SMBClientProbe.c Inas/SMB/SMBClientProbe.h
  Inas/SMB/PathSandbox.c Inas/SMB/PathSandbox.h
  Inas/SMB/DialectPolicy.h
  Inas/SMB/FilesystemShare.c Inas/SMB/FilesystemShare.h
  Inas/Services/DiscoveryUDP.c Inas/Services/DiscoveryUDP.h
)
CLANG_FORMAT="$(command -v clang-format || true)"
if [[ -z "$CLANG_FORMAT" ]]; then
  CLANG_FORMAT="$(xcrun --find clang-format 2>/dev/null || true)"
fi
if [[ -n "$CLANG_FORMAT" ]]; then
  echo "clang-format: checking Inas C sources"
  "$CLANG_FORMAT" --dry-run --Werror "${C_FORMAT_FILES[@]}"
else
  echo "clang-format: not installed, skipping"
fi

if command -v swift-format >/dev/null 2>&1; then
  echo "swift-format: linting Inas and InasTests"
  swift-format lint --recursive Inas InasTests \
    || echo "swift-format: style differences (not failing)"
else
  echo "swift-format: not installed, skipping"
fi

pick_destination() {
  python3 - <<'PY'
import json, subprocess, sys
raw = subprocess.check_output(["xcrun", "simctl", "list", "devices", "available", "-j"])
data = json.loads(raw)
preferred = ["iPhone 17", "iPhone 16", "iPhone 16 Pro", "iPhone 15 Pro", "iPhone 15"]
found = []
for runtime, devices in data.get("devices", {}).items():
    if "iOS" not in runtime:
        continue
    for dev in devices:
        if dev.get("isAvailable") and "iPhone" in dev.get("name", ""):
            found.append(dev["name"])
for name in preferred:
    if name in found:
        print(f"platform=iOS Simulator,name={name}")
        sys.exit(0)
if found:
    print(f"platform=iOS Simulator,name={found[0]}")
    sys.exit(0)
sys.exit("no available iPhone simulator")
PY
}

DESTINATION="${DESTINATION:-$(pick_destination)}"
echo "xcodebuild test destination: $DESTINATION"

SIGNING_ARG=""
if [[ "${CI:-}" == "true" ]]; then
  SIGNING_ARG="CODE_SIGNING_ALLOWED=NO"
fi

xcodebuild \
  -project Inas.xcodeproj \
  -scheme Inas \
  -destination "$DESTINATION" \
  -skipPackagePluginValidation \
  $SIGNING_ARG \
  test
