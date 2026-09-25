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

SHA-256 of the **digest basis** of each result — the integer-domain radix
ciphertext obtained via `into_raw_parts()` — computed from trivially encrypted
operands `a = 1_000_000`, `b = 337` (trivial encryption is used precisely because
it is deterministic, giving every machine an identical starting ciphertext).

add 849a75d4a4d8c66320709df1cc550016e980c15a3aca5ac340970b19df6709bf
sub f9aaa247ff013815857ae8664d9729d35ca3fa90d344a1a815640fcc4c6d7cce
select 2bd6f509e1d432abe4d0e98b920c34fc2c48420f38a96e236d8124c3383ebe08
le e771ad484477fe8846732e23162740866e78bc78820f812d155f32c74aac75df

**`le` is new (2026-08-28) and the other three are unchanged**, which is the
point: the boolean basis was added without moving the integer one. For a
boolean the raw part is a single shortint block with no wrapper members, so
unlike the integer case there is nothing to exclude — the whole raw part is
the basis.

*Why it was missing.* Every reference value was uint-producing, so no fixture
could fail on the boolean class, and digesting a boolean returned an error
rather than a wrong answer. The test had in fact computed `le` all along and
never printed it — printing it would have failed. **A fixture set that cannot
fail on a class does not test that class**, and this one could not.

### ⚠️ Basis change 2026-08-20 — these values changed; the computation did not

**If you are comparing an old build against a new one, read this before
concluding anything.** The figures above replace an earlier set taken over a
different object, and a mismatch between the two sets is expected rather than
alarming:

```
add    758d0b97d88bde5f68a99d589b1919cf9d2053b5ff5a3fcc5d0d6a50f5aa159a   (superseded)
sub    963ec46976b76da359d866ca6252dbe2ed13eafa263709c4ff0407622fef421a   (superseded)
select bf87fb019115b09567b32d5f8f7369ab089cb3d9e4e3ea4f8dffc316ea6063fc   (superseded)
```

**What changed.** The old values hashed `serialize_handle` — the **wire form**,
which is the whole `FheUint64` wrapper. Op-stream protocol **v0.4** (declared
2026-08-19) defines `ctDigest` over the **integer-domain ciphertext only**,
excluding the wrapper's `id`, `tag` and `re_randomization_metadata`.

**Why.** tfhe 1.7 serialises those last two, and both are *application-settable*.
A digest over the wrapper would let two honest coprocessors produce different
digests from identical computation — a disagreement the fraud game cannot
distinguish from cheating. Narrowing the digested object also makes it robust to
further members appearing upstream: 1.7 added a fourth; a fifth would otherwise
walk straight into consensus-critical bytes.

**What did not change.** The computation, the library version, the build profile,
the machine. Only what is hashed. The old values remain correct *for the wire
form*, which `serialize_handle` still produces — clients submit that shape and the
admission tests round-trip through it.

*Verified when the basis moved: `digest_basis_excludes_the_wrapper` asserts the
basis is strictly smaller than the wire form, so the exclusion is checked rather
than assumed.*

### Where `digest_basis` was introduced, because the history does not say

**`digest_basis` was added to `backend.rs` in commit `a7c8fe8`, under a message
describing documentation work it does not contain.** So `git log -- fhe/backend-adapter/`
and `git bisect` will **not** surface this function to someone looking for when
the attested-digest basis was introduced. This note is where that search ends
instead.

**How it happened:** two repositories were committed in one sitting and the
messages crossed — a documentation message landed on a code commit. The
corresponding documentation work is properly committed in the documentation
repository, so nothing was lost; the code commit simply carries the wrong
description. It also reached `main` directly, with no pull request, which is why
the function's tests and documentation were reviewed while the implementation
was not.

**Why the message was not rewritten.** Correcting it means a force-push that
changes every subsequent hash, and this project's working records cite those
hashes as evidence — so the rewrite must be paired with an old-to-new remap
applied across those records in the same sitting, coordinated across two
engineers. That was judged to cost more than it returns, and the practical loss
was only ever *discoverability*, which this note restores.

*A false message with a correction beside it is a more honest record than a
rewritten history that reads as though it never happened.*


TFHE-rs 1.7.0, release profile, CPU **without** AVX-512 (Intel Ultra 7 258V).

## What the digest binds

The basis binds **how a value was computed**, not only what it is: adding a
trivially encrypted zero moves one byte per block, and a subtraction result
that is cryptographically identical to a direct encryption still digests
differently. Measurement: `tests/radix_basis.rs`.

**The two consequences that follow are normative and live in the op-stream
protocol (v0.5 §8), not here** — the backend library version is
consensus-critical rather than recommended, and a coprocessor must not
optimise the stream even in value-preserving ways. They were parked in this
file while they had no other home; that home now exists and this section
must not restate them, or the constraint has two records that can drift.

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
