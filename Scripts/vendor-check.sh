#!/usr/bin/env bash
# Apply Vendor/patches to the fa52e91 libsmb2 baseline and require the
# result to match Vendor/libsmb2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! git rev-parse --verify fa52e91 >/dev/null 2>&1; then
  echo "vendor-check: baseline commit fa52e91 is missing" >&2
  exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/inas-vendor.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

git archive fa52e91 Vendor/libsmb2 | tar -x -C "$TMP"

PATCHES=( "$ROOT"/Vendor/patches/*.patch )
if [[ ! -e "${PATCHES[0]}" ]]; then
  echo "vendor-check: no patches in Vendor/patches" >&2
  exit 1
fi

for patch in "${PATCHES[@]}"; do
  echo "applying $(basename "$patch")"
  ( cd "$TMP" && git apply --unsafe-paths --whitespace=nowarn "$patch" )
done

if ! diff -ru "$TMP/Vendor/libsmb2/lib" "$ROOT/Vendor/libsmb2/lib" \
      || ! diff -ru "$TMP/Vendor/libsmb2/include" "$ROOT/Vendor/libsmb2/include"; then
  echo "vendor-check: patched baseline does not match Vendor/libsmb2" >&2
  exit 1
fi

echo "vendor-check: ok (${#PATCHES[@]} patches)"
