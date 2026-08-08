#!/usr/bin/env python3
"""
Celar M1 bake-off harness — runs the required op set against ANY backend behind
the frozen ABI and emits the report tables from doc/celar-backend-bakeoff-spec.md.

Runs today against MockBackend (proves the framework end-to-end). In Phase 1 an
engineer registers ZamaBackend / OpenFHEBackend in adapter.available_backends()
and the identical harness produces the real measured numbers.

Usage:  python3 bakeoff_harness.py
"""

from __future__ import annotations
import sys, time, os, statistics

# make the adapter importable regardless of CWD
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "fhe", "backend-adapter"))
import adapter  # noqa: E402

MASK64 = (1 << 64) - 1
T_QUORUM = 79   # §7.7 permissionless committee threshold

# Real FHE operations cost hundreds of milliseconds, so repetition counts are
# small by necessity. Medians over few samples are noisy; treat them as
# order-of-magnitude figures, not precise costs.
BENCH_REPS = 5
TRANSFER_REPS = 3

# ---- shared test corpus (spec §2): zero, max, overflow boundary, mid, random ----
CORPUS = [
    ("zero",       0,                  1),
    ("max",        MASK64,             500),
    ("boundary",   MASK64 - 1,         2),
    ("mid",        1_000_000_000,      999),
    ("random",     0xDEADBEEFCAFE,     42),
]


def secret(be, value, k=64):
    """
    An operand that is genuinely encrypted, submitted the way a client would.

    Trivial encryption is NOT usable here: it produces noiseless
    public-value ciphertexts which the backend short-circuits (measured at
    239x-1372x faster than real operands) and which carry no noise, so they
    exercise neither real cost nor the noise budget. Reserve trivial
    encryption for values that really are public.
    """
    return be.verify_input(be.encode_input(value, k), b"proof")


def timed(fn, *a, reps=BENCH_REPS):
    """median ms over reps (warm)."""
    fn(*a)  # warm
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn(*a)
        xs.append((time.perf_counter() - t0) * 1e3)
    return statistics.median(xs)


def run_correctness(be) -> tuple[int, int]:
    """§3.1 functional correctness vs plaintext oracle. Returns (passed, total)."""
    passed = total = 0
    for name, a_pt, b_pt in CORPUS:
        for b_pt2 in (b_pt, (b_pt * 7 + 3) & MASK64):
            ha = secret(be, a_pt)
            hb = secret(be, b_pt2)
            checks = {
                "add": (be._oracle(be.add(ha, hb)), (a_pt + b_pt2) & MASK64),
                "sub": (be._oracle(be.sub(ha, hb)), (a_pt - b_pt2) & MASK64),
                "le":  (be._oracle(be.le(ha, hb)), 1 if a_pt <= b_pt2 else 0),
            }
            # branchless transfer (§6): ok = a<=bal ; m = select(ok, a, 0)
            ok = be.le(ha, hb)
            m = be.select(ok, ha, be.trivial_encrypt(0, 64))
            checks["select/transfer"] = (be._oracle(m), a_pt if a_pt <= b_pt2 else 0)
            for got, want in checks.values():
                total += 1
                passed += (got == want)
    return passed, total


def run_transfer_e2e(be):
    """§3.3 full §6 branchless transfer, timed."""
    def one():
        a = secret(be, 100)
        bal_s = secret(be, 500)
        bal_r = secret(be, 50)
        ok1 = be.le(a, bal_s)
        cap = be.sub(be.trivial_encrypt(MASK64, 64), bal_r)
        ok2 = be.le(a, cap)
        ok = be.and_(ok1, ok2)
        m = be.select(ok, a, be.trivial_encrypt(0, 64))
        be.add(bal_r, m); be.sub(bal_s, m)
    return timed(one, reps=TRANSFER_REPS)


def input_proof_rejects(be) -> bool:
    """§3.1 — a bad proof must be rejected. a good one admitted"""
    ct = be.encode_input(5,64)
    try:
        be.verify_input(ct, b"")        # empty proof must be refused
        return False
    except Exception:
        pass
    try:
        be.verify_input(ct,b"\x01")     # valid proof must be admitted
        return True
    except Exception:
        return False

def report(name, be):
    caps = be.caps()
    print("\n" + "=" * 74)
    print(f"BAKE-OFF REPORT — backend: {name}  ({caps.name})")
    print("=" * 74)

    # 3.1 correctness & security (DISQUALIFIER)
    passed, total = run_correctness(be)
    corr_ok = (passed == total)
    proof_ok = input_proof_rejects(be)
    print("\n[3.1] Correctness & security (DISQUALIFIER)")
    print(f"  functional correctness vs oracle : {passed}/{total}   {'PASS' if corr_ok else 'FAIL'}")
    print(f"  bad-proof rejection              : {'PASS' if proof_ok else 'FAIL'}")
    print(f"  p_fail derivation provided       : {caps.p_fail_derivation}")
    print(f"  lambda_stat supported (>=64)     : {caps.lambda_stat_supported}   "
          f"{'PASS' if caps.lambda_stat_supported >= 64 else 'FAIL'}")

    # 3.2 determinism (DISQUALIFIER)
    print("\n[3.2] Determinism (DISQUALIFIER for fraud model)")
    print(f"  CPU-path bit-reproducible        : {caps.cpu_deterministic}   "
          f"{'PASS' if caps.cpu_deterministic else 'FAIL — cannot define fraud game'}")
    print(f"  GPU available (may diverge, OK)  : {caps.gpu_available}")

    # 3.3 performance (WEIGHTED) — synthetic under mock, real under real adapters
    s3, s4  = secret(be, 3), secret(be, 4)
    t_add   = timed(be.add, s3, s4)
    t_le    = timed(be.le,  s3, s4)
    _cond   = be.le(s3, s4)          # select's condition is an ebool
    t_sel   = timed(be.select, _cond, s3, s4)
    t_pbs   = timed(be.pbs_op, secret(be, 9))
    t_xfer  = run_transfer_e2e(be)
    t_dec   = timed(be.threshold_decrypt, secret(be, 9), T_QUORUM)
    print(f"\n[3.3] Performance (WEIGHTED)  [real operands, "
          f"n={BENCH_REPS}; mock timings are synthetic]")
    print(f"  add            : {t_add:8.4f} ms")
    print(f"  le (compare)   : {t_le:8.4f} ms")
    print(f"  select         : {t_sel:8.4f} ms")
    print(f"  pbs-bearing op : {t_pbs:8.4f} ms")
    print(f"  transfer e2e   : {t_xfer:8.4f} ms")
    print(f"  local decrypt  : {t_dec:8.4f} ms  (single-key stand-in — NOT")
    print("                              comparable to the §7.3 < 2000 ms")
    print("                              threshold target: no committee, no")
    print("                              partials, no network, no flooding)")

    # 3.5 legal
    print("\n[3.5] Legal & sustainability (WEIGHTED)")
    print(f"  license   : {caps.license}")
    print(f"  FTO status: {caps.fto_status}   "
          f"{'(gating if open)' if caps.fto_status=='open' else ''}")

    # verdict
    disq = []
    if not corr_ok: disq.append("correctness")
    if not proof_ok: disq.append("input-proof")
    if caps.lambda_stat_supported < 64: disq.append("lambda_stat")
    if not caps.cpu_deterministic: disq.append("determinism")
    print("\n  VERDICT:", "ELIMINATED (" + ", ".join(disq) + ")" if disq
          else "passes disqualifiers → proceeds to weighted scoring")


def main():
    backends = adapter.available_backends()
    print("Celar M1 bake-off harness")
    print(f"corpus: {[c[0] for c in CORPUS]}   committee t={T_QUORUM}")
    for name, be in backends.items():
        report(name, be)
    print("\n" + "=" * 74)
    print("Framework OK. Phase-1: register real backends in adapter.available_backends()")
    print("and re-run — identical harness emits real measured numbers.")
    print("=" * 74)


if __name__ == "__main__":
    main()
