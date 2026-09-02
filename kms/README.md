# kms — threshold key management (§7)

Distributed key generation, noise-flooded threshold decryption and
re-encryption, authorization and fraud proofs, proactive resharing,
permissioned committee mode, and the ACL read path.

**This directory IS the `celar-kms` Rust crate** (flattened from
`kms/celar-kms/` on 2026-08-16 — older docs may cite the nested path).
Upstream: `zama-ai/kms` git-pinned **v0.13.22**; the protocol crate is
`threshold-execution` (the `core/threshold` path in some docs is stale).
Consumers of the git dep must mirror upstream's `[patch.crates-io]` forks —
see the comment in `Cargo.toml`.

## What's built

| Piece | State |
|---|---|
| **DKG** — local n-party + real MPC offline phase (`--preproc secure`) + gRPC/mTLS ceremony (`celar-kms-node`, one process per member) | 🟡 code-complete; awaits 𝒫_FHE params, genesis-scale run, §7.1 quorum-mapping decision |
| **Resharing** — epoch-chained `reshare.json`, pk_G invariant, recovery via `--drop-role` | 🟡 local milestone; secure dual-ring offline + ceremony mode pending |
| **Committee mode** — §7.7 vetted roster, CA-cert pinning, roster digest through fragments → transcript | 🟡 rules enforced + unit-tested at genesis scale; genesis-scale ceremony pending |
| **ACL verify** — `celar-acl-verify`: ICS23 (AppHash(H+1) ⊢ `evm` store ⊢ IAVL) + reference MPT path | **ICS23 ratified (§4.1, 2026-08-16)** — the production read path; `mpt.rs` is the oracle |

## The AppHash trust boundary (a precondition of fraud-proof verification; normative)

An ICS23 chain is only as trustworthy as its root. A caller-supplied AppHash
(RPC response, file, flag) relocates the committee's trust to whoever served
it — so `header_trust.rs` makes the boundary mechanical:

- `AppHashSource::LightClientVerified` — the **only** source the KMS trust
  path accepts. Constructed from headers verified by a Tendermint light
  client (trusted checkpoint + validator-set signatures); the KMS service
  wires the actual light client into this seam once seat signing keys land.
- `AppHashSource::UnverifiedCallerSupplied` — what `--header`/`--app-hash`
  produce. **Refused by default.** Dev/test flows opt in with
  `--allow-unverified-header`, and the verdict is permanently tainted
  (`root=UNVERIFIED-DEV (not a trusted verdict)`).
- The authorization predicate takes an `AdmittedAppHash`, never a raw hash —
  the type system is the enforcement. Refusal on an unverifiable root is the
  same posture as the ACL read path's refusal property.

Transcripts are public artifacts: config, upstream pin, pk_G digest,
per-party share **commitments** — never shares. `--write-dev-keys` runs are
DEV ONLY and their outputs are gitignored key material.

## Quick start

```bash
cd kms
cargo build --release
cargo test  --release                       # config/transcript/mpt/acl/committee tests

# local DKG (dev): dummy | secure offline phase
./target/release/celar-dkg run --parties 4 --preproc secure --out /tmp/dkg-dev --write-dev-keys
./target/release/celar-dkg verify --transcript /tmp/dkg-dev/transcript.json --keys-dir /tmp/dkg-dev

# proactive reshare: epoch 1 from a previous run's dir
./target/release/celar-dkg reshare --in /tmp/dkg-dev --out /tmp/epoch1 [--drop-role 3]
./target/release/celar-dkg verify-reshare --transcript /tmp/epoch1/reshare.json \
  --prev /tmp/dkg-dev/transcript.json --keys-dir /tmp/epoch1

# mTLS ceremony with a vetted roster:
./target/release/celar-certs --ca-prefix party --ca-count 4 -n 1 -o certs
echo "127.0.0.1 core1.party1 core1.party2 core1.party3 core1.party4" | sudo tee -a /etc/hosts
./target/release/celar_kms_node roster-init --parties 4 --certs-dir certs --out roster.json
./target/release/celar_kms_node gen-configs --certs-dir certs --roster roster.json --out-dir ceremony
for i in 1 2 3 4; do ./target/release/celar_kms_node run --config ceremony/node_00$i.json & done; wait
./target/release/celar_kms_node collect --dir ceremony
```

## Hard-won operational notes

- **TLS identity trinity:** dial hostname = cert subject = MPC identity, one
  string. The cert generator's `cert_party1-core1.pem` certifies the name
  `core1.party1`; IPs are rejected for TLS.
- **Round timeouts are load-bearing:** heavy MPC compute between sync rounds
  drops shares at default timeouts (`round_timeout_secs`, default 600).
- **tfhe pin:** this tree pins **=1.7.0**, via the upstream kms revision
  `main@c6b0fdd3` — the same tfhe version the compute backend uses, so no
  ciphertext-format reconciliation is needed between them. *(Historical
  note: the tree originally pinned =1.6.1 at upstream v0.13.22; the re-pin
  is recorded in `Cargo.toml`. Re-pin to the next upstream release tag once
  one ships on 1.7.x.)*
- The reconstruction-quorum ↔ upstream sharing-degree mapping is an **open
  §7.1 spec question** carried in `src/config.rs` — attach no security claims
  to the quorum number until it is resolved.
