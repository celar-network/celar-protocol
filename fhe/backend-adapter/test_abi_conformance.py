#!/usr/bin/env python3
"""
Conformance: the backend adapter covers the frozen ABI.

This exists because adapter.py silently drifted from ABI.md — ops were
missing and two signatures modelled the wrong side of the boundary. The
mapping table in ABI.md is now the source of truth, and this test reads it,
so the two files cannot diverge again without a failure.

Run: python3 test_abi_conformance.py
"""
from __future__ import annotations
import inspect
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import adapter  # noqa: E402

ABI_MD = Path(__file__).parent / "ABI.md"

# Ops the precompile exposes that a backend deliberately does NOT implement.
# Keep in sync with the "Backend surface" section of ABI.md.
CHAIN_ONLY_OPS = {"allow"}

# ABI op -> backend method where the names deliberately differ: the chain-side
# request ops are served by the backend's threshold crypto (see ABI.md).
ALIASES = {
    "requestReencrypt": "threshold_reencrypt",
    "requestReveal": "threshold_decrypt",
}

# Expected parameter count (excluding self) per backend method.
EXPECTED_ARITY = {
    "verify_input": 2,          # ciphertext, proof
    "trivial_encrypt": 2,       # value, k
    "add": 2, "sub": 2,
    "le": 2, "lt": 2, "eq": 2,
    "and_": 2, "or_": 2, "not_": 1,
    "select": 3,                # cond, a, b
    "cast": 2,                  # handle, k
    "threshold_decrypt": 2,     # handle, t
    "threshold_reencrypt": 3,   # handle, t, user_pubkey
}

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    if cond:
        print(f"  ok   {msg}")
    else:
        print(f"  FAIL {msg}")
        failures.append(msg)


def abi_ops() -> set[str]:
    """Op names from the ABI tables: any row whose first cell contains only
    backticked names, optionally separated by / or ,."""
    ops: set[str] = set()
    for line in ABI_MD.read_text().splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        first = line.strip("|").split("|")[0].strip()
        names = re.findall(r"`(\w+)`", first)
        residue = re.sub(r"`\w+`", "", first).strip()
        if names and re.fullmatch(r"[/,\s]*", residue):
            ops.update(names)
    return ops


def backend_method_for(op: str) -> str:
    """ABI op name -> backend method name (camelCase to snake, keyword fix)."""
    if op in ALIASES:
        return ALIASES[op]
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", op).lower()
    return snake + "_" if snake in {"and", "or", "not"} else snake


def main() -> int:
    ops = abi_ops()
    print(f"ABI ops discovered in ABI.md: {len(ops)}")
    check(len(ops) >= 15, "ABI.md parsed (>=15 ops found)")

    print("\n-- every ABI op maps to a backend method (or is chain-only) --")
    for op in sorted(ops):
        if op in CHAIN_ONLY_OPS:
            check(not hasattr(adapter.FHEBackend, backend_method_for(op)),
                  f"{op}: chain-only, absent from FHEBackend")
            continue
        check(hasattr(adapter.FHEBackend, backend_method_for(op)),
              f"{op}: FHEBackend.{backend_method_for(op)} present")

    print("\n-- signatures --")
    for name, arity in EXPECTED_ARITY.items():
        fn = getattr(adapter.FHEBackend, name, None)
        if fn is None:
            check(False, f"{name}: missing")
            continue
        got = len(inspect.signature(fn).parameters) - 1  # drop self
        check(got == arity, f"{name}: takes {arity} args (got {got})")

    print("\n-- MockBackend is concrete (no abstract methods left) --")
    try:
        be = adapter.MockBackend()
        check(True, "MockBackend instantiates")
    except TypeError as e:
        check(False, f"MockBackend abstract: {e}")
        return 1

    print("\n-- semantics locked by earlier fixes --")
    ct = be.encode_input(42, 64)
    check(be._oracle(be.verify_input(ct, b"\x01")) == 42,
          "verify_input admits a valid proof")
    try:
        be.verify_input(ct, b"")
        check(False, "verify_input refuses an empty proof")
    except Exception:
        check(True, "verify_input refuses an empty proof")

    h = be.trivial_encrypt(7, 64)
    r_alice = be.threshold_reencrypt(h, 79, b"alice-key")
    r_bob = be.threshold_reencrypt(h, 79, b"bob-key")
    check(r_alice != r_bob, "re-encryption is bound to the recipient key")
    check(r_alice == be.threshold_reencrypt(h, 79, b"alice-key"),
          "re-encryption is deterministic for a given recipient")

    print("\n" + ("CONFORMANCE OK" if not failures
                  else f"{len(failures)} FAILURE(S)"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
