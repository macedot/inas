#!/usr/bin/env bash
# SMB share benchmark: sequential and parallel read/write over a mounted
# share plus small-file ops. Usage:
#
#   Scripts/bench.sh <smb-url-without-share> [label]
#   e.g. Scripts/bench.sh //inas:correct1@iPhone.local:14455 device
#        Scripts/bench.sh //inas:correct1@127.0.0.1:14455 simloop
#
# The mount point is managed by the script (/tmp/inas-bench). Sizes and
# runs are fixed so results are comparable across code versions.
set -euo pipefail

URL="${1:?usage: bench.sh <smb-url-without-share> [label]}"
LABEL="${2:-bench}"
MOUNT=/tmp/inas-bench
SIZES_MB=(1 10 100)
RUNS=3
PARALLEL=4
SMALL_FILES=200

say() { printf '\n=== %s ===\n' "$*"; }

# dd with 1 MiB blocks; prints seconds on stderr via `date`.
timed_dd() { # src dst
  local t0 t1
  t0=$(python3 -c 'import time; print(time.time())')
  dd if="$1" of="$2" bs=1m 2>/dev/null
  t1=$(python3 -c 'import time; print(time.time())')
  python3 -c "print(f'{$t1-$t0:.3f}')"
}

mbps() { # bytes seconds
  python3 -c "print(f'{$1/1048576/$2:.1f}')"
}

best_of() { # runs of "seconds" numbers -> min
  python3 -c "import sys; print(f'{min(float(x) for x in sys.argv[1:]):.3f}')" "$@"
}

median_of() {
  python3 -c "
import statistics, sys
print(f'{statistics.median(float(x) for x in sys.argv[1:]):.3f}')" "$@"
}

say "mounting $URL at $MOUNT"
mkdir -p "$MOUNT"
remount() {
  umount -f "$MOUNT" 2>/dev/null || true
  mount_smbfs "$URL/inas" "$MOUNT"
}
remount
BENCH_DIR="$MOUNT/bench-$$"
mkdir -p "$BENCH_DIR"

WORK=$(mktemp -d /tmp/inas-bench-files.XXXXXX)
trap 'umount -f "$MOUNT" 2>/dev/null; rm -rf "$WORK" "$MOUNT"' EXIT

for mb in "${SIZES_MB[@]}"; do
  dd if=/dev/zero of="$WORK/test-$mb.bin" bs=1m count="$mb" 2>/dev/null
done

RESULTS="$LABEL-results.txt"
: > "$RESULTS"

for mb in "${SIZES_MB[@]}"; do
  bytes=$((mb * 1048576))

  say "WRITE ${mb}MB sequential x$RUNS"
  wtimes=()
  for _ in $(seq $RUNS); do
    s=$(timed_dd "$WORK/test-$mb.bin" "$BENCH_DIR/w-$mb.bin")
    wtimes+=("$s")
    echo "  run: ${s}s ($(mbps "$bytes" "$s") MB/s)"
  done
  wb=$(best_of "${wtimes[@]}"); wm=$(median_of "${wtimes[@]}")

  say "READ ${mb}MB sequential x$RUNS (remount drops client cache)"
  rtimes=()
  for _ in $(seq $RUNS); do
    remount
    s=$(timed_dd "$BENCH_DIR/w-$mb.bin" /dev/null)
    rtimes+=("$s")
    echo "  run: ${s}s ($(mbps "$bytes" "$s") MB/s)"
  done
  rb=$(best_of "${rtimes[@]}"); rm_=$(median_of "${rtimes[@]}")

  {
    echo "seq-write-${mb}MB best $(mbps "$bytes" "$wb") MB/s (${wb}s) median $(mbps "$bytes" "$wm") MB/s"
    echo "seq-read-${mb}MB  best $(mbps "$bytes" "$rb") MB/s (${rb}s) median $(mbps "$bytes" "$rm_") MB/s"
  } >> "$RESULTS"

  say "PARALLEL ${PARALLEL}x${mb}MB"
  pt0=$(python3 -c 'import time; print(time.time())')
  pids=()
  for i in $(seq $PARALLEL); do
    dd if="$WORK/test-$mb.bin" of="$BENCH_DIR/p-$i-$mb.bin" bs=1m 2>/dev/null &
    pids+=($!)
  done
  wait "${pids[@]}"
  pt1=$(python3 -c 'import time; print(time.time())')
  psec=$(python3 -c "print(f'{$pt1-$pt0:.3f}')")
  pbytes=$((bytes * PARALLEL))
  pmbps=$(mbps "$pbytes" "$psec")
  echo "par-write-${mb}MB x$PARALLEL aggregate $pmbps MB/s (${psec}s)" >> "$RESULTS"
  echo "  aggregate: ${pmbps} MB/s"

  say "PARALLEL READ ${PARALLEL}x${mb}MB (remount drops client cache)"
  remount
  pt0=$(python3 -c 'import time; print(time.time())')
  pids=()
  for i in $(seq $PARALLEL); do
    dd if="$BENCH_DIR/p-$i-$mb.bin" of=/dev/null bs=1m 2>/dev/null &
    pids+=($!)
  done
  wait "${pids[@]}"
  pt1=$(python3 -c 'import time; print(time.time())')
  psec=$(python3 -c "print(f'{$pt1-$pt0:.3f}')")
  pmbps=$(mbps "$pbytes" "$psec")
  echo "par-read-${mb}MB  x$PARALLEL aggregate $pmbps MB/s (${psec}s)" >> "$RESULTS"
  echo "  aggregate: ${pmbps} MB/s"
done

say "SMALL FILES (${SMALL_FILES} creates)"
st0=$(python3 -c 'import time; print(time.time())')
for i in $(seq $SMALL_FILES); do
  echo "x" > "$BENCH_DIR/small-$i.txt"
done
st1=$(python3 -c 'import time; print(time.time())')
ssec=$(python3 -c "print(f'{$st1-$st0:.3f}')")
sops=$(python3 -c "print(f'{$SMALL_FILES/$ssec:.0f}')")
echo "small-creates $sops ops/s (${ssec}s for $SMALL_FILES)" >> "$RESULTS"
echo "  ${sops} ops/s"

say "SMALL FILES (${SMALL_FILES} deletes)"
st0=$(python3 -c 'import time; print(time.time())')
for i in $(seq $SMALL_FILES); do
  rm -f "$BENCH_DIR/small-$i.txt"
done
st1=$(python3 -c 'import time; print(time.time())')
ssec=$(python3 -c "print(f'{$st1-$st0:.3f}')")
sops=$(python3 -c "print(f'{$SMALL_FILES/$ssec:.0f}')")
echo "small-deletes $sops ops/s (${ssec}s for $SMALL_FILES)" >> "$RESULTS"
echo "  ${sops} ops/s"

say "cleanup"
rm -rf "$BENCH_DIR"

say "RESULTS ($LABEL)"
cat "$RESULTS"
