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
  Inas/SMB/Srvsvc.c Inas/SMB/Srvsvc.h
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

# Physical iPhone only. Never fall back to a simulator.
IPHONE_UDID="${IPHONE_UDID:-00008130-001C78EC18EB8D3A}"
if ! xcrun devicectl device info details --device "$IPHONE_UDID" >/dev/null 2>&1; then
  echo "test.sh: physical iPhone $IPHONE_UDID is not connected" >&2
  exit 1
fi
DESTINATION="${DESTINATION:-platform=iOS,id=$IPHONE_UDID}"
echo "xcodebuild test destination: $DESTINATION"

xcodebuild \
  -project Inas.xcodeproj \
  -scheme Inas \
  -destination "$DESTINATION" \
  -skipPackagePluginValidation \
  test
