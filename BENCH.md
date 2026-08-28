# iNAS SMB performance benchmarks

All numbers from `Scripts/bench.sh` against the **iPhone-hosted share**
(DEBUG build, `INAS_SIM_*` autostart, port 14455), mounted from the Mac
via mount_smbfs over WiFi. Read phases remount first so client-side
caches never mask the numbers. Sequential runs: best and median of 3.
"par" = 4 concurrent streams, aggregate throughput.

The server signs and seals every PDU (ENCRYPT_DATA share flag), so all
numbers include full crypto overhead.

## Baseline (v0.0.5, unmodified) — 2026-08-27

| Test                       | Throughput |
|----------------------------|-----------:|
| seq write 1MB              |  7.5 MB/s |
| seq write 10MB             | 28.5 MB/s |
| seq write 100MB            | 33.8 MB/s |
| seq read 1MB               |  7.2 MB/s |
| seq read 10MB              | 21.3 MB/s |
| seq read 100MB             | 32.6 MB/s |
| par write 1MB x4 aggregate | 11.7 MB/s |
| par write 10MB x4          | 25.5 MB/s |
| par write 100MB x4         | 32.7 MB/s |
| par read 1MB x4            | 16.2 MB/s |
| par read 10MB x4           | 28.1 MB/s |
| par read 100MB x4          | 34.5 MB/s |
| small creates              | 36 ops/s |

## Phase 1b: skip signature on sealed PDUs (pdu.c) — 2026-08-27

Within run-to-run noise of 1a (all sizes ~equal). Kept anyway: it halves
the per-PDU crypto work (battery/CPU headroom) and is spec-sanctioned.
Small-file creates at 35 ops/s, unchanged.

## Phase 1c: 4MB max PDUs — skipped

Both directions plateau at the same ~34-35 MB/s regardless of payload
size, and parallel streams do not raise it: the cap is the WiFi link,
not per-PDU overhead. Larger PDUs cannot raise a link cap; skipped to
avoid added risk (PDU size limits, credit_charge edge cases).

## Phase 2: deferred file-I/O worker pool — 2026-08-28

READ/WRITE handlers hand the blocking pread/pwrite to a worker pool
(max 8 in flight) and return "deferred"; replies are queued from the
server thread when completions drain through the existing
extra_fdset/extra_service hooks. First bench run looked like a massive
regression (creates 4 ops/s) — not reproducible on rerun (environmental:
device thermals/WiFi). Verified deferred replies grant credits correctly
(instrumented: client requests 256, server grants 256, charge 8 per
512KB write).

| Test                       | Baseline | 1a  | Phase 2 | Δ vs baseline |
|----------------------------|---------:|----:|--------:|--------------:|
| seq write 1MB              |  7.5     | 9.3 | 10.5    | +40% |
| seq read 1MB               |  7.2     | 9.9 | 12.2    | +69% |
| par write 1MB x4           | 11.7     | 16.0| 16.9    | +44% |
| par read 1MB x4            | 16.2     | 17.5| 16.4    | +1%  |
| seq write 100MB            | 33.8     | 34.4| 34.5    | +2%  |
| seq read 100MB             | 32.6     | 33.9| 34.7    | +6%  |
| par write 100MB x4         | 32.7     | 34.6| 34.7    | +6%  |
| par read 100MB x4          | 34.5     | 36.5| 37.1    | +8%  |
| small creates              | 36/s     | 34/s| 95/s    | +164%|

## Conclusions

- **Small/latency-bound operations improved dramatically** (small-file
  creates 2.6x, 1MB transfers +40-69%): the crypto-churn fix plus the
  worker pool removed most per-operation serialization.
- **Large transfers are WiFi-link-capped at ~34-37 MB/s** between this
  Mac and iPhone; no server-side change can raise that. On faster links
  (WiFi 6 / docked USB) the parallel engine now has headroom: parallel
  streams no longer serialize behind each other's disk I/O.
- Kept: 0014 cached AES cryptors, 0015 signature skip, deferred I/O
  worker pool, per-connection handle cleanup. Skipped: 4MB PDUs.
