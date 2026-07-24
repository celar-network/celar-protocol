#!/usr/bin/env python3
"""
Celar FHE backend adapter interface (drives the M1 bake-off harness).

A backend is anything implementing `FHEBackend`. The harness (bakeoff_harness.py)
knows nothing about Zama vs OpenFHE — it calls this interface only, which IS the
frozen ABI (ABI.md) expressed for the test driver.

Provided here:
  - FHEBackend           : the abstract interface every backend implements
  - MockBackend          : a plaintext-shadow backend so the harness runs TODAY
                           (proves the framework; obviously not real crypto).

To add a real backend, a Phase-1 engineer writes e.g. ZamaBackend(FHEBackend)
that FFIs into TFHE-rs, or OpenFHEBackend(FHEBackend) into OpenFHE, keeping the
identical method signatures. The harness and report code do not change.
"""

from __future__ import annotations
import time
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


# A handle is 32 bytes in the real ABI; here we model it as an int id plus the
# backend's private ciphertext store. The harness only ever passes handles back.
Handle = int


@dataclass
class BackendCaps:
    """Static facts a backend must publish for the bake-off report (spec §3)."""
    name: str
    p_fail_derivation: str          # §3.1 — MUST be provided; disqualifier if absent
    lambda_stat_supported: int      # §3.1 — must be >= 64 (or 40+log2 Qmax)
    cpu_deterministic: bool         # §3.2 — disqualifier if False
    gpu_available: bool
    license: str                    # §3.5
    fto_status: str                 # §3.5 — 'clean' | 'open' | 'n/a'


class FHEBackend(ABC):
    """The frozen ABI (ABI.md), driver-side. Every method mirrors a precompile op."""

    @abstractmethod
    def caps(self) -> BackendCaps: ...

    # A. input admission
    @abstractmethod
    def verify_input(self, plaintext: int, k: int, proof_ok: bool) -> Handle: ...
    @abstractmethod
    def trivial_encrypt(self, value: int, k: int) -> Handle: ...

    # B. homomorphic compute
    @abstractmethod
    def add(self, a: Handle, b: Handle) -> Handle: ...
    @abstractmethod
    def sub(self, a: Handle, b: Handle) -> Handle: ...
    @abstractmethod
    def le(self, a: Handle, b: Handle) -> Handle: ...        # -> ebool handle
    @abstractmethod
    def select(self, cond: Handle, a: Handle, b: Handle) -> Handle: ...
    @abstractmethod
    def pbs_op(self, a: Handle) -> Handle: ...               # a PBS-bearing op

    # C. KMS gateway (threshold path)
    @abstractmethod
    def threshold_decrypt(self, h: Handle, t: int) -> int: ...
    @abstractmethod
    def threshold_reencrypt(self, h: Handle, t: int) -> bytes: ...

    # test-only: reveal the modeled plaintext for oracle comparison
    @abstractmethod
    def _oracle(self, h: Handle) -> int: ...


class MockBackend(FHEBackend):
    """
    Plaintext-shadow backend. Stores the true plaintext behind each handle so the
    harness can exercise the full op set and check correctness against an oracle.
    Timings are synthetic (a fixed per-op cost) — real timings come from real
    adapters. Its ONLY jobs: prove the harness runs end-to-end, and give the
    correctness path something to compare against.
    """
    MASK = (1 << 64) - 1

    def __init__(self):
        self._store: dict[Handle, int] = {}
        self._next: Handle = 1

    def _put(self, v: int) -> Handle:
        h = self._next
        self._next += 1
        self._store[h] = v & self.MASK
        return h

    def caps(self) -> BackendCaps:
        return BackendCaps(
            name="MockBackend",
            p_fail_derivation="N/A (mock, no crypto)",
            lambda_stat_supported=64,
            cpu_deterministic=True,
            gpu_available=False,
            license="internal",
            fto_status="n/a",
        )

    def verify_input(self, plaintext, k, proof_ok):
        if not proof_ok:
            raise ValueError("input proof rejected (verifyInput)")
        if not (0 <= plaintext < (1 << k)):
            raise ValueError("range check failed")
        return self._put(plaintext)

    def trivial_encrypt(self, value, k):
        return self._put(value)

    def add(self, a, b):   return self._put(self._store[a] + self._store[b])
    def sub(self, a, b):   return self._put(self._store[a] - self._store[b])
    def le(self, a, b):    return self._put(1 if self._store[a] <= self._store[b] else 0)
    def select(self, cond, a, b):
        return self._put(self._store[a] if self._store[cond] else self._store[b])
    def pbs_op(self, a):
        # model a PBS-bearing op as identity-through-a-table (real backends bootstrap)
        return self._put(self._store[a])

    def threshold_decrypt(self, h, t):
        return self._store[h]
    def threshold_reencrypt(self, h, t):
        return hashlib.sha256(str(self._store[h]).encode()).digest()

    def _oracle(self, h):
        return self._store[h]


# convenience: registry the harness reads
def available_backends() -> dict[str, FHEBackend]:
    """Real backends register here in Phase 1: e.g. 'zama': ZamaBackend()."""
    return {"mock": MockBackend()}
