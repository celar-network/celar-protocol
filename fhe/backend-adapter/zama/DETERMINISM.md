# Determinism of the compute path

The fraud game requires that re-executing an operation reproduces the result
bit-for-bit. A verifier who recomputes a disputed operation must be able to
distinguish dishonesty from an honest difference; any non-determinism destroys
that distinction. The frozen interface states it as: *CPU-path determinism —
bit-identical output across independent CPU builds.*

Note what determinism does **not** mean here. Encryption is randomised by
design: two encryptions of the same value differ, and must, or the scheme
would be broken. What must be reproducible is **computation over identical
input ciphertext**.

## Reference fingerprints

SHA-256 of the serialised result of each operation, computed from trivially
encrypted operands `a = 1_000_000`, `b = 337` (trivial encryption is used
precisely because it is deterministic, giving every machine an identical
starting ciphertext).

add 758d0b97d88bde5f68a99d589b1919cf9d2053b5ff5a3fcc5d0d6a50f5aa159a
sub 963ec46976b76da359d866ca6252dbe2ed13eafa263709c4ff0407622fef421a
select bf87fb019115b09567b32d5f8f7369ab089cb3d9e4e3ea4f8dffc316ea6063fc


TFHE-rs 1.7.0, release profile, CPU **without** AVX-512 (Intel Ultra 7 258V).

## Reproducing

```bash
cargo test --release --test determinism -- --nocapture fingerprint
```

## Verified

**Repeated execution.** Identical input ciphertext produces byte-identical
output across repeated runs of `add`, `sub` and `select`.

**Thread count.** Parallel reductions are a classic source of non-determinism:
if partial results accumulate in completion order rather than a fixed order,
the answer depends on how many threads happened to run. That is the more
dangerous failure mode, since it needs no unusual hardware — a coprocessor on
four cores would simply disagree with one on sixty-four. Tested clean: the
fingerprints are identical at `RAYON_NUM_THREADS` = 1, 2, 4 and 8.

```bash
for n in 1 2 4 8; do
  RAYON_NUM_THREADS=$n cargo test --release --test determinism \
    -- --nocapture fingerprint 2>/dev/null | grep FINGERPRINT
done
```

Worth re-running where the core count is materially different; this was
checked only up to eight.

**Compile-time vectorisation flag.** Building with the `avx512` feature
enabled and disabled produced identical fingerprints — but see below, since
the available hardware cannot execute those paths either way.

## What is still unverified

**Cross-hardware reproducibility.** TFHE-rs enables `avx512` as a *default*
feature, wiring into `tfhe-fft` and `tfhe-ntt`, and those libraries select
code paths by detecting the CPU **at runtime**. The same binary can therefore
compute differently on different machines. Whether vectorised paths produce
bit-identical results to the scalar fallback has not been tested, because no
AVX-512 hardware was available.

**This is the remaining open question.** Anyone with an AVX-512-capable machine
(Intel Xeon Scalable, Intel 10th–11th gen consumer, AMD Zen 4/5) can settle it
by running the fingerprint command and comparing. First confirm the flags are
actually exposed, since hypervisors sometimes mask them:

```bash
grep -o -m1 'avx512[a-z]*' /proc/cpuinfo | sort -u
```

A mismatch would mean honest validators on different hardware disagree, and
the fraud game cannot tell that apart from fraud.

## Design consequence

Runtime CPU dispatch is incompatible with bit-reproducibility. The interface
already anticipates a version of this by treating GPU as an unverified
accelerator that may diverge, with the CPU path as ground truth. Vectorised
CPU paths belong in the same category.

The reference implementation should therefore pin a baseline instruction set —
`default-features = false` plus `RUSTFLAGS="-C target-cpu=x86-64-v2"`, so no
code path is chosen by probing the processor — accepting lower throughput in
exchange for reproducibility. The production coprocessor may use every
accelerator available, since its results are checked against the reference by
sampled re-execution rather than trusted directly.

Note that this makes restricting operators to particular hardware unnecessary.
Hardware restriction is a brittle proxy: it must be verified, it ages, and it
can be misreported. Making the computation hardware-independent removes the
variable at the source, after which every divergence detected by sampled
re-execution genuinely is misbehaviour rather than a different processor.
