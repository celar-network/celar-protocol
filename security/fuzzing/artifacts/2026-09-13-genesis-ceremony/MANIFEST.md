# Genesis-scale DKG ceremony — measurement artifact (2026-09-13)

Genesis-shape distributed key generation at the genesis committee size, run to
produce the by-measurement figures the whitepaper §7.1 clause needs (peak memory
per seat, wall time, a verified transcript). This is a SHAPE run: the test
parameter set and dev key handling, not a production key.

## Configuration

- Committee: **c = 30**, reconstruction quorum t = 7 (session threshold), §7.7 genesis mode.
- Preprocessing: secure-large (real MPC offline; the PRSS path is structurally
  refused at this committee size).
- Parameters: `PARAMS_TEST_BK_SNS` (test set). Transport: mTLS gRPC, cross-box.
- Topology: 30 seats over 2 hosts, 15 seats/host.
- Hosts: 2 × (64 vCPU, 247 GiB RAM, Linux 7.0.0-1012-aws).

## Results

- **pk_G** = `6a37986ba16abfd3c57bfd55e55963922346fbafe2b24c70ba28e999ed7c5592`
  — agreed by all 30 seats. Verified two ways: every per-seat compressed-key
  dump hashes identically, and the merged transcript passes pk_G equality across
  all 30 fragments (`COLLECT-OK`).
- **Transcript:** `transcript.json` (30 fragments, corrupt set empty).
- **Wall time:** 27,755 s ≈ **7.71 h**. Latency-bound (~50% CPU): the cost is
  per-round network round-trips across the O(n²) reliable-broadcast traffic at
  n = 30, not raw compute.
- **Peak resident set:** **10.9 GiB/seat** (10.91 / 10.92 across the two hosts,
  from `/usr/bin/time -v`), reached during the online keygen phase (the offline
  phase sits near ~1.2 GiB/seat). Provisioning consequence: a 64 GiB host cannot
  hold 8 seats (8 × 10.9 ≈ 87 GiB) — budget ≥ ~12–16 GiB/seat.

## Operational findings (fixed during the run)

1. **Port-range firewall rule off-by-one.** The inbound rule covered the seat
   ports up to N−1, excluding the top port. One seat was unreachable from the
   start; the reliable broadcast evicted it and the session cascaded to abort.
   Fix: widen the rule to cover the whole port range (verified with a live
   listener before relaunch). Lesson: probe the actual range boundaries, not a
   sample port.
2. **Finish-and-exit race.** A seat aborted its MPC server the instant it
   finished and exited; the online keygen needs every peer reachable until the
   last seat finishes, so fast finishers dropped connections slower peers still
   needed, cascading via connection-refused. Fix: a finished seat keeps serving
   until the operator stops it, after all fragments are collected.
3. **Memory ceiling.** Prior estimate was ~4–8 GiB/seat; the measured peak is
   10.9 GiB, so hosts sized for the estimate OOM-killed seats mid-keygen. Fix:
   right-size hosts to the measured peak.

## Provenance

- celar-protocol rev: `5bb723b`
- Upstream (threshold-*) fork pin: `b79e997`
- Files in this directory: `transcript.json` (the merged genesis transcript;
  public — pk_G digest + per-seat share COMMITMENTS only, no share material),
  and this manifest. Per-seat run logs and `/usr/bin/time` reports were retained
  on the hosts; secret share dumps were never exported.
