# Bake-off artifacts

Each run is stored as a pair: `bakeoff-<utc>.txt` (harness output) and
`env-<utc>.txt` (machine, toolchain, build profile, git commit). A figure is
citable only if its environment manifest is present.

## Superseded runs — do not cite

**2026-08-08 (both runs).** Performance tables are **void**. The harness
built operands with trivial encryption — noiseless, public-value ciphertexts
that the library short-circuits — so the timings measured optimized handling
of public data rather than encrypted computation. Direct comparison on the
same machine showed real client-encrypted operands are 239x (add), 869x (le)
and 1372x (eq) slower. The reported ordering was itself the tell: addition
appeared slower than comparison, which reverses on real ciphertext.

Correctness results from those runs stand (40/40 against the plaintext
oracle); only the timings are void.
