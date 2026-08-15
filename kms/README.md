# kms — Track B: threshold key management (§7)

DKG (B1), noise-flooded threshold decrypt/re-encrypt (B2/B3), authorization +
fraud proofs (B4), proactive resharing (B5), permissioned committee mode (B6),
plus G10 (the KMS ACL read path) — per `doc/engg/celar-onboarding-track-b.md`.

## celar-kms (B1 skeleton)

Local n-party DKG over `zama-ai/kms` (git-pinned **v0.13.22**; the protocol
crate is `threshold-execution` — the older `core/threshold` path in some docs
is stale), producing a **published, re-verifiable transcript**
(`transcript.json`: config, upstream pin, pk_G digest, per-party share
commitments — never shares themselves).

```bash
cd kms/celar-kms
cargo build --release                      # first build compiles the kms stack + tfhe 1.6.1
cargo test  --release                      # config + transcript unit tests
./target/release/celar-dkg run --parties 4 --out /tmp/dkg-dev --write-dev-keys
./target/release/celar-dkg verify --transcript /tmp/dkg-dev/transcript.json --keys-dir /tmp/dkg-dev
```

Honest skeleton labels: dummy preprocessing (real offline phase is a swap
point), local in-memory networking (gRPC/mTLS per S2 later), test parameter
set (𝒫_FHE selection is separate work). The reconstruction-quorum ↔ upstream
sharing-degree mapping is an **open spec question** carried explicitly in
`config.rs` — do not attach security claims to the quorum number until §7.1's
mapping is resolved for the implementation.

Note: this tree pins **tfhe =1.6.1** (kms workspace pin); Track A's backend
uses 1.7.0. No build conflict (separate trees) — ciphertext-format
reconciliation is flagged for B2.
