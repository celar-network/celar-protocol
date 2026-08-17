# Celar — Architecture and Implementation Walkthrough

A technical tour of what exists, how it fits together, and what is
deliberately not built yet. Written to be read by someone who knows FHE and
Cosmos and will ask hard questions.

---

## 1. What Celar is

A Layer 1 blockchain where contract state can stay encrypted. Balances,
amounts, and contract variables live as ciphertext; contracts compute on them
without decrypting; decryption requires authorisation recorded on chain and a
threshold of an independent committee.

The scheme is TFHE (CGGI) via Zama's TFHE-rs. The chain is Cosmos SDK +
Cosmos EVM, so contracts are ordinary Solidity and wallets are ordinary
Ethereum wallets.

## 2. The three layers, and why the split exists

```
┌──────────────────────────────────────────────────────────────┐
│ CHAIN (Go, Cosmos EVM)                                       │
│  validators execute Solidity; the FHE precompile records     │
│  operations SYMBOLICALLY and owns authorisation state        │
│  fast, deterministic, every validator agrees                 │
└───────────────────────┬──────────────────────────────────────┘
                        │ op-stream: "h3 = add(h1,h2)"
                        ▼
┌──────────────────────────────────────────────────────────────┐
│ COPROCESSOR (Rust, TFHE-rs)                                  │
│  performs the real homomorphic arithmetic on ciphertext       │
│  slow (hundreds of ms/op), heavy, horizontally scalable       │
└───────────────────────┬──────────────────────────────────────┘
                        │ holds no keys
                        ▼
┌──────────────────────────────────────────────────────────────┐
│ KMS COMMITTEE (threshold, staked, separate from validators)   │
│  the only holder of key material; decrypts or re-encrypts     │
│  ONLY when the on-chain ACL authorises it                     │
└──────────────────────────────────────────────────────────────┘
```

**Why not compute FHE inside consensus?** A single encrypted 64-bit
comparison costs ~200 ms on commodity CPU (measured, §8). If validators did
that during block execution, block times would collapse. The industry moved
the same way: Zama's original in-consensus fhEVM was deprecated in favour of
this split.

**Consequence that matters:** validators stay commodity hardware. Heavy
accelerators live in the coprocessor layer, where centralisation is contained
and slashable, rather than in the validator set where it would centralise
consensus.

## 3. Repository map

```
celar-protocol/
├── chain/celard/                  ← the node (Go)
│   ├── cmd/evmd/main.go             entry point: package main, func main()
│   │   └── cmd/root.go              CLI tree; `start` builds the app
│   ├── app.go                       assembles keepers, modules, precompiles
│   ├── config/
│   │   ├── bech32.go                address prefix: celar1…
│   │   ├── config.go                default home ~/.celard
│   │   └── permissions.go           module-account permissions
│   ├── precompiles/fhe/           ← Celar's own precompile
│   │   ├── abi.json                 15 operations, Solidity-facing
│   │   ├── types.go                 address 0x…0900, gas, permission enum
│   │   ├── fhe.go                   selector dispatch + operation logic
│   │   ├── storage.go               slot derivation, handle registry, ACL
│   │   ├── STORAGE-LAYOUT.md        the storage specification
│   │   └── *_test.go                determinism, registry, authorisation
│   └── precisebank/                 forked: 9↔18 decimal reconciliation
├── chain/devnet/                    make-devnet, patch-genesis, run-node
├── fhe/backend-adapter/
│   ├── ABI.md                     ← the frozen interface (the authority)
│   ├── adapter.py                   Python interface + plaintext mock
│   ├── test_abi_conformance.py      fails if the two sides drift
│   └── zama/                      ← the real FHE backend (Rust)
│       ├── Cargo.toml               manifest; pins tfhe 1.7.0
│       ├── pyproject.toml           maturin config for the Python module
│       ├── src/lib.rs               crate root, key generation
│       ├── src/backend.rs           ciphertext store + the ten operations
│       ├── src/python.rs            PyO3 binding (feature-gated)
│       └── tests/{ops,admission}.rs correctness against a plaintext oracle
└── security/fuzzing/
    ├── bakeoff_harness.py           correctness + timing harness
    ├── run-bakeoff.sh               runs it, writes an environment manifest
    └── artifacts/                   kept logs; a figure needs a manifest
```

---

## 4. Layer one: the chain

### 4.1 Startup

```
cmd/evmd/main.go        package main → func main()
  └── cmd.NewRootCmd()  builds the CLI (init, keys, genesis, comet, start)
      └── "start" → NewExampleApp()   [app.go]
          ├── keepers in dependency order:
          │     auth → bank → precisebank → staking → distribution
          │     → gov → mint → IBC → feemarket → EVM → erc20
          ├── precompile map (stock 15 + ours at 0x…0900)
          ├── module manager: init-genesis / begin-block / end-block order
          └── ante handler chain (signature, fee, gas)
      └── CometBFT drives it: InitChain once, then FinalizeBlock forever
```

`app.go` is the whole assembly. Registering our precompile is additive — no
fork of the upstream library:

```go
staticPrecompiles := precompiletypes.DefaultStaticPrecompiles(/* … */)
celarFHE, err := celarfhe.NewPrecompile()
staticPrecompiles[common.HexToAddress(celarfhe.CelarFHEPrecompileAddress)] = celarFHE
app.EVMKeeper = app.EVMKeeper.WithStaticPrecompiles(staticPrecompiles)
```

### 4.2 What a precompile actually is

Native node code parked at a reserved address. To Solidity it looks like a
contract call; no bytecode runs. Ethereum ships ~10 (`0x01` ecrecover,
`0x02` sha256…), Cosmos EVM adds its own at `0x800`–`0x807`, Celar adds one
at **`0x900`**. Necessary because FHE cannot be expressed in EVM bytecode.

Call path:

```
wallet / eth_call
  → JSON-RPC :8545 → mempool → block
    → x/vm module executes the EVM
      → interpreter hits CALL 0x…0900
        → static precompile map lookup
          → fhe.Precompile.Run(evm, contract, readonly)
```

### 4.3 Dispatch, and the three classes of operation

`Run` reads the 4-byte selector, resolves it against `abi.json`, and
dispatches:

**Compute — stateless.** No ciphertext, no cryptography: derive a handle and
return it.

```go
h := p.deriveHandle(method, argBz)   // keccak256(domainTag ‖ method ‖ args)
p.registerHandle(evm.StateDB, h, contract.Caller(), ktype, readonly)
return method.Outputs.Pack(h)
```

Determinism is by construction — the handle is a pure function of the
operation and its arguments, so every validator computes the same value.

**Authorisation — a state write.**

```go
meta := p.getMeta(db, h)
if !metaExists(meta)          { return errors.New("unknown handle") }
if metaOwner(meta) != caller  { return errors.New("not the handle owner") }
p.grantPerm(db, h, grantee, bit)      // acl[h][grantee] |= permission
```

**Committee requests — guarded, then emitted.**

```go
if err := p.checkServable(db, caller, method.Name, argBz); err != nil {
    return nil, err                    // re-encrypt: owner or grantee
}                                      // reveal: explicit per-handle grant
return p.RunNativeAction(evm, contract, /* emit the request event */)
```

### 4.4 Why the call-budget question mattered

Cosmos EVM caps *stateful* precompile calls at 20 per transaction
(`MaxPrecompileCalls`). A confidential transfer needs 10–15 FHE operations,
so the cap would have bound on the core product.

The counter increments only inside `RunNativeAction` (the Cosmos multistore
snapshot path). Compute operations never touch it, and ACL writes go to **EVM
storage** via `StateDB.SetState`, which is journaled by the EVM itself. So
the cap never binds — and the ACL gains a *better* revert story, because the
EVM journal is inherently correct across nested calls.

### 4.5 Storage layout

Everything lives in the precompile account's own EVM storage, at the exact
slots the Solidity compiler would compute:

```
handleMeta[h]      = keccak256(h ‖ uint256(1))
                     → bytes 0-19 owner │ 20 type │ 21 flags(bit0 = exists)

acl[h][grantee]    = keccak256(pad32(grantee) ‖ keccak256(h ‖ uint256(2)))
                     → permission bitmask: 1 compute │ 2 reencrypt │ 4 reveal
```

Solidity-compatible layout is a deliberate interoperability decision: the KMS
and fraud-proof verifiers are **outside** the chain, and they read these
slots through standard **EIP-1186** proofs (`eth_getProof`: account proof →
storage root, storage proof → slot). No bespoke Merkle verifier inside the
KMS, which is the most dangerous place to put new cryptographic code.

### 4.6 Ownership, and the attack it prevents

Handles are public — visible in calldata, events, storage. If `allow` had no
ownership check, an attacker could read your balance handle off the chain,
grant themselves `reveal`, and the KMS would honour it, because the ACL *is*
the authorisation root. The KMS cannot tell a legitimate grant from a stolen
one; that is why the ACL write is the security boundary.

So ownership is recorded by the chain at creation time, from the EVM's own
unforgeable `contract.Caller()`, and registration is **write-once**
(first-writer-wins). In practice the owner is the ConfidentialERC20 contract,
because it is what computes balance handles — so authorisation policy lives
in audited contract code.

---

## 5. Layer two: the FHE backend (Rust)

### 5.1 Cargo, for readers coming from Make or Go

| Concept | Cargo | Go |
|---|---|---|
| manifest | `Cargo.toml` | `go.mod` |
| lockfile | `Cargo.lock` (committed here — determinism needs exact versions) | `go.sum` |
| build | `cargo build --release` → `target/release/` | `go build -o path ./cmd/x` |
| test | `cargo test` compiles **and runs** test binaries | `go test ./...` |
| executable | requires `[[bin]]` or `src/main.rs` | requires `package main` |

**This crate produces no executable.** It declares:

```toml
[lib]
crate-type = ["cdylib", "rlib"]   # cdylib → .so for Python; rlib → Rust linking
```

so `cargo build --release` yields `libcelar_zama.so` and
`libcelar_zama.rlib` — libraries. Nothing to launch. It is *called*: today by
Python, later by the coprocessor daemon (which will have a `main.rs` and be
launchable like `celard`).

`--release` is not optional: TFHE in a debug build is roughly two orders of
magnitude slower.

### 5.2 How TFHE-rs is used

Two keys with different powers:

```rust
let (client_key, server_key) = generate_keys(ConfigBuilder::default().build());
set_server_key(server_key);   // thread-local; enables computation
```

- **ClientKey** — encrypts and decrypts. The secret.
- **ServerKey** — bootstrapping/evaluation keys. Lets a machine *compute* on
  ciphertext while learning nothing. This is what a coprocessor holds.

Under the hood a `FheUint64` is a **radix** value: a vector of small
ciphertext blocks. That explains our measured costs — addition must propagate
carries across all blocks, while comparison reduces as a tree — which is why
`add` (360 ms) is *slower* than `le` (209 ms) here.

### 5.3 Two kinds of encryption, and the trap

```rust
FheUint64::try_encrypt_trivial(v)   // "trivial": NOISELESS, value is public
FheUint64::encrypt(v, &client_key)  // real: noise, actually secret
```

Trivial encryption is legitimate for genuinely public constants (the literal
`0`, the overflow bound `u64::MAX`). But it is **not** representative:
TFHE-rs short-circuits on it, and it carries no noise.

We measured the difference on identical operations:

| op | trivial | real | ratio |
|---|---|---|---|
| add | 1.5 ms | 365 ms | **239×** |
| le | 0.24 ms | 208 ms | **869×** |
| eq | 0.14 ms | 186 ms | **1372×** |

The bake-off harness had been benchmarking trivial ciphertexts. Its numbers
were void — and its correctness tests never exercised the noise budget at
all, despite the interface requiring operations to survive boundary noise
states. Both are fixed; the void run is retained and labelled in
`security/fuzzing/artifacts/README.md`.

**The tell was the ordering, not the magnitude:** `add` appearing *faster*
than `le` contradicts how radix TFHE behaves. Worth keeping as a review
habit — check that relative costs match the physics.

### 5.4 The ciphertext store

```rust
pub type Handle = u64;

pub enum Ct {
    Uint { ct: FheUint64, width: u8 },   // encrypted integer + declared width
    Bool(FheBool),                        // encrypted boolean
}

pub struct Backend {
    store: HashMap<Handle, Ct>,
    next: Handle,
}
```

The tag is a safety property, not bookkeeping: an encrypted *boolean* and an
encrypted *integer* are different types, and conflating them must be an error
rather than a wrong answer. That tagging is what caught two latent bugs in
the harness (a `select` given an integer condition; a boolean passed as a
value branch) which the plaintext mock had silently tolerated for months.

### 5.5 The operations

```rust
add(a,b)            → &x + &y                    // wraps at 2^64, per the interface
sub(a,b)            → &x - &y
le/lt/eq(a,b)       → x.le(y) / x.lt(y) / x.eq(y) → FheBool
and/or/not          → &x & &y, &x | &y, !&x       // on FheBool
select(cond,a,b)    → c.if_then_else(x, y)        // the branchless primitive
cast(a,k)           → &x & mask(k)                // truncate to width
```

`select` is the heart of the design. There is no branching on encrypted data
— **both** results are computed and one is chosen homomorphically, so
execution reveals nothing about the condition. The whole confidential
transfer is built from it:

```rust
affordable = le(amount, sender_balance)
headroom   = sub(MAX, recipient_balance)
fits       = le(amount, headroom)
ok         = and(affordable, fits)
moved      = select(ok, amount, zero)     // zero when not ok
new_sender    = sub(sender_balance, moved)
new_recipient = add(recipient_balance, moved)
```

A failed transfer and a successful one are **indistinguishable**: same
operations, same gas, no revert, no event difference. Insufficient funds
subtract zero.

### 5.6 What is real and what is a stand-in

| | status |
|---|---|
| encryption / decryption | real TFHE-rs |
| the ten compute operations | real |
| ciphertext serialisation | real (bincode) |
| input-proof verification | **stub** — non-empty check; the real proof gate is a separate workstream |
| threshold decryption | **stand-in** — single-key local decrypt |
| threshold re-encryption | **stand-in** — recipient-bound digest; keeps the property that material for one recipient is useless to another |

The stand-ins are labelled in the source. They are not on any production
path, and the committee workstream owns the real protocol.

### 5.7 The Python binding

```rust
#[pyclass] pub struct ZamaBackend { inner: Backend, ck: ClientKey }

#[pymethods] impl ZamaBackend {
    #[new] fn new() -> Self { /* generate keys, set_server_key */ }
    fn add(&mut self, a: Handle, b: Handle) -> PyResult<Handle> { … }
    /* … one method per interface operation … */
}

#[pymodule] fn celar_zama(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ZamaBackend>()?; Ok(())
}
```

`maturin develop --release` compiles this to a `.so` and installs it as an
importable module. The harness then drives real cryptography through the same
interface the mock implements — swap the backend, change no test code.

One subtlety worth knowing: pyo3's `extension-module` feature tells the
linker the interpreter will supply Python symbols. Right for the shared
library, but it breaks standalone Rust test binaries, so the binding sits
behind an optional `python` feature that only maturin enables. `cargo test`
therefore needs no Python development headers.

---

## 6. The interface contract

`ABI.md` is the authority, frozen since the backend decision. Both sides
conform to it, and `test_abi_conformance.py` parses its tables and fails if
they drift — because they *had* drifted: six operations were missing from the
Python interface, `verify_input` modelled the caller's view instead of the
validator's (taking a plaintext and a boolean "the proof is fine"), and
`threshold_reencrypt` had no recipient key, so it could not model
re-encryption at all.

The precompile surface and the backend surface deliberately differ in one
place: **`allow` has no backend method.** It writes consensus-state ACL, not
ciphertext. No TFHE-rs primitive corresponds to it, and a second
authorisation source inside a backend could only be redundant or wrong.
Authorisation is enforced where it is provable.

---

## 7. The gap: nothing connects the two halves yet

```
CHAIN                            BACKEND
symbolic handles (keccak)        real ciphertexts
ownership registry               real homomorphic arithmetic
ACL authorisation                real encrypt / decrypt
        │                                ▲
        └────── op-stream ───────────────┘
               NOT BUILT
```

The design (settled by research, not yet implemented): validators emit a
deterministic instruction stream from the precompile via `StateDB.AddLog` —
EVM logs are deterministic, journaled, and need no Cosmos context, which
matters because the compute path is stateless. The coprocessor consumes the
stream over gRPC/mTLS and returns ciphertext commitments.

It is deliberately unbuilt: the stream's wire format — ordering rule, event
schema, envelope versioning, attestation and commitment signatures,
abort/timeout parameters — is not frozen. A consumer written against an
unfrozen protocol would be rebuilt. Integrity will be sampled re-execution
against a pinned CPU reference implementation, with a version-upgradeable
commitment envelope so verifiable-FHE proofs can replace sampling later
without a state migration.

---

## 8. Measured performance

Real client-encrypted operands, TFHE-rs 1.7.0, release build, GPU off,
avx512 on, Intel Ultra 7 258V / 8 cores (TFHE-rs parallelises internally, so
these are multi-core latencies), n=5. **Order of magnitude, not precise
costs.**

| operation | cost |
|---|---|
| comparison (`le`) | 209 ms |
| bootstrap-bearing probe | 218 ms |
| branchless `select` | 332 ms |
| radix `add` | 360 ms |
| **full confidential transfer** | **≈ 1.85 s** |

Correctness: **40/40 against a plaintext oracle on noise-bearing
ciphertext**, across a corpus of zero, maximum, the overflow boundary, a mid
value and an arbitrary one.

**Not yet characterised, and declared as such** rather than asserted:
p_fail derivation for the parameter set; λ_stat; and bit-identical CPU output
across independent builds — the last is open partly because the build enables
`avx512`, and vectorised FFT paths may not be reproducible across
heterogeneous hardware. That matters because the fraud game's ground truth
requires reproducibility. The backend therefore reports these as unmeasured,
which the harness currently prints as "eliminated" — vocabulary that
overstates the case and needs an "uncharacterised" state.

Figures are from TFHE-rs **default** parameters, not a Celar-chosen set.

---

## 9. Running it

```bash
# chain: build, generate a devnet, start it
cd chain && ./bootstrap.sh

# FHE backend: Rust tests (no Python needed)
cd fhe/backend-adapter/zama && cargo test --release

# build the Python module and run the harness with kept artifacts
python3 -m venv ../.venv && ../.venv/bin/pip install maturin
source ../.venv/bin/activate && maturin develop --release
../../../security/fuzzing/run-bakeoff.sh
```

The devnet EVM chain id is `23529`; add the network at
`http://127.0.0.1:8545` with currency `CELAR`. The same seed phrase yields
the same account in both MetaMask (`0x…`) and the node's keyring
(`celar1…`) — Ethereum key derivation, two address encodings, one balance.

---

## 10. Honest summary of state

**Working and tested:** the chain (9-decimal native token, three-validator
consensus, EVM compatibility); the FHE precompile (symbolic handles,
ownership registry, ACL authorisation, committee-request guards); the FHE
backend (all ten operations, real encryption, the full branchless transfer
verified against a plaintext oracle).

**Stubbed, with the real work assigned elsewhere:** input-proof
verification; threshold decryption and re-encryption.

**Not built, and deliberately so:** the op-stream that connects chain to
coprocessor, pending a protocol freeze; the coprocessor service and its
transport; the fraud game; the shielded pool; the bridge.

**Known open questions:** CPU determinism across builds under vectorised
code paths; p_fail derivation and λ_stat for a Celar-chosen parameter set;
whether small-width types should be specialised rather than masked 64-bit
values (which would change narrow-type performance).
