# Celar FHE Precompile ABI — FROZEN at M1

**Status:** FROZEN. This is the backend-agnostic seam (whitepaper §16). Both Zama TFHE-rs/fhEVM and OpenFHE CGGI implement this identical interface; application/contract code binds only to this, never to a backend. Changing this ABI is a hard-fork-class event.

## Types

- `handle` — 32 bytes, `h = H_k(ct_id)` (§3). Opaque reference to ciphertext material in the FHE data plane. All FHE values (euint8…euint64, ebool) are handles at the contract boundary.
- `euint{k}` / `ebool` — handles whose plaintext type is tracked in on-chain metadata, not in the handle bytes.
- `proof` — byte string: the input ZKPoK π_in (§5).
- `addr` — 20-byte account address.

## Precompile operations

Grouped by the three planes they touch. Every op is deterministic w.r.t. its inputs and the pinned backend (the determinism requirement, §8).

### A. Input admission (validator-verified, §5)
| Op | Signature | Notes |
|----|-----------|-------|
| `verifyInput` | `(bytes ciphertext, proof) → handle` | Verifies π_in (well-formedness + range + knowledge); registers the handle. Rejects on invalid proof. Gates state admission. |
| `trivialEncrypt` | `(uint64 value, uint8 k) → handle` | Public constant → ciphertext (no proof; value is public). |

### B. Homomorphic compute (coprocessor-evaluated, §6, §8)
| Op | Signature | Notes |
|----|-----------|-------|
| `add` / `sub` | `(handle a, handle b) → handle` | euint_k arithmetic; silent wrap (§3 sizing). |
| `le` / `lt` / `eq` | `(handle a, handle b) → handle` (ebool) | Encrypted comparison. |
| `and` / `or` / `not` | `(handle…) → handle` (ebool) | Boolean combinators. |
| `select` | `(handle cond_ebool, handle a, handle b) → handle` | **The branchless primitive (§6).** The ONLY path encrypted predicates may flow into. |
| `cast` | `(handle, uint8 k') → handle` | euint width change. |

> Deploy-time analyzer invariant (§3.2): no contract bytecode may route an ebool into a revert/branch — only into `select`. Enforced at deployment, not here.

### C. Access control + KMS gateway (§3, §7.4)
| Op | Signature | Notes |
|----|-----------|-------|
| `allow` | `(handle, addr, perm) → void` | Writes the on-chain ACL. `perm ∈ {compute, reencryptToSelf, reveal}`. Caller must own the handle. Sole authorization root the KMS honors. |
| `requestReencrypt` | `(handle, bytes userPubKey) → requestId` | Emits a KMS re-encryption request (§7.3). Servable iff caller ∈ acl[handle] as owner. Partials combined client-side. |
| `requestReveal` | `(handle) → requestId` | Emits a public-decrypt request (§7.2). Servable iff `(handle, reveal)` granted. |

## Handle lifecycle

`verifyInput`/`trivialEncrypt`/compute ops produce handles → `allow` writes ACL → compute proceeds under `compute` grants → `requestReencrypt`/`requestReveal` are the only exits to plaintext, each gated by the ACL and producing signed KMS partials (fraud-provable, §7.4).

## Backend contract (what an adapter must guarantee)

1. **Correctness:** every op matches the plaintext oracle on the full euint64 range incl. boundary noise states.
2. **p_fail ≤ 2⁻⁶⁴** per PBS-bearing op (§7.2) — with a published derivation for the chosen 𝒫_FHE.
3. **Flooding budget** supports λ_stat = 64 per radix digit (§7.2).
4. **CPU-path determinism:** bit-identical output across independent CPU builds (the fraud-game ground truth, §8). GPU may diverge (unverified accelerator).
5. **No hidden plaintext path:** the adapter never materializes a decryptable whole outside the threshold KMS.

Adapters live beside this file: `adapter.py` defines the Python-side interface the harness drives; production adapters wrap TFHE-rs (Rust) / OpenFHE (C++) behind it.

### Backend surface — the mapping, and what is deliberately absent

This document specifies the **precompile** surface (what Solidity may call).
`adapter.py` specifies the **backend** surface (what an FHE library must
provide). They overlap but are not identical:

| ABI op | Backend method | Note |
|---|---|---|
| `verifyInput` | `verify_input(ciphertext, proof)` | backend verifies the proof and admits the ciphertext |
| `trivialEncrypt` | `trivial_encrypt(value, k)` | |
| `add`, `sub` | `add`, `sub` | |
| `le`, `lt`, `eq` | `le`, `lt`, `eq` | |
| `and`, `or`, `not` | `and_`, `or_`, `not_` | trailing underscore: Python keywords |
| `select` | `select` | |
| `cast` | `cast` | |
| `allow` | — | **chain-side only** (see below) |
| `requestReencrypt` | `threshold_reencrypt(h, t, user_pubkey)` | the request is chain-side; the backend performs the threshold crypto |
| `requestReveal` | `threshold_decrypt(h, t)` | as above |

**Why `allow` has no backend method.** It writes the ACL, which is consensus
state in the precompile's own EVM storage — the authorization root the KMS
honors and the evidence base for the fraud proof. It is a state write, not a
cryptographic operation: no TFHE-rs or OpenFHE primitive corresponds to it, so
requiring it of every backend would mandate a method none can meaningfully
implement. Authorization is enforced on chain, where it is provable; a second
copy inside a backend could only be redundant or wrong.

**Harness-only methods.** `pbs_op` (a PBS-bearing operation used as a
performance probe) and `_oracle` (test-only plaintext shadow for correctness
comparison) are instruments of the bake-off harness, not ABI ops; no on-chain
surface exposes them.
