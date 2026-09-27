# Live attestation vector

`live-devnet.json` holds attestations the coprocessor produced from a real
chain, so the Rust signer and the Go verifier can be checked against **each
other** rather than each against a document.

## Why it is here rather than in either tree

The signed preimage is built twice — once in `fhe/coprocessor` to sign, once in
`chain/celard/fraudevidence/types` to recover — out of a domain string, a chain
id, a stream position, a result handle and a ciphertext digest. The low-s rule
is likewise implemented twice. Before this file, each side was tested against a
hand-written vector, which is each side agreeing with whoever wrote the vector.
Repo-root `testdata/` is neutral ground, the same reasoning as
`testdata/epochcommit/`.

## Provenance

Produced by `cargo run --example live` in `fhe/coprocessor`, against a devnet
built by `chain/celard/scripts/devnet.sh`:

- chain id 262144 (`celar-devnet-2`), token deployed and one `mint`
- five attestations: one from the constructor's `asEuint64(0)`, four from the
  mint
- the coprocessor signs with a fixed dev key, so the identity in
  `coprocessor_id` is not meant to verify against any roster. What is under
  test is the preimage and the signature convention, not who signed.

Hex is unprefixed and lowercase. `chain_id` is in the file deliberately: the
preimage binds it, so a vector without it cannot be checked.

## Regenerating

```
celard start --home ~/celar-devnet-solo --chain-id celar-devnet-2 \
  --minimum-gas-prices 0ncelar --json-rpc.enable &
cd fhe/coprocessor && cargo run --example live
```

Two properties worth knowing before you trust a regenerated file:

- **Identical input gives identical bytes.** A restart of the same chain
  reproduces the same handles, digests and signatures — verified by comparing
  two runs across a node restart. A diff here means something genuinely moved.
- **Two of the five are byte-identical in handle and digest** (log 0 and log 3
  of the mint): the same `trivialEncrypt` emitted twice, because the chain must
  not optimise the stream. They differ only in signature, since the position is
  in the preimage. A regenerated file that collapses them to one is a bug in the
  chain, not in the fixture.

The Go side skips rather than fails when this file is absent, so a fresh clone
without a devnet is not blocked. A missing vector is therefore invisible in CI
— if that ever matters, the skip is the thing to change.
