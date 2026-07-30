# Celar FHE Precompile — Handle & ACL Storage Layout (v1)

Design for the on-chain handle registry and ACL held in the EVM storage of the
FHE precompile account (`0x0000000000000000000000000000000000000900`). This is
the authorization root the KMS honors and the state the fraud proof cites.

Spec basis: whitepaper §3 (handles, `acl[h]`, owning-contract write rule) and
§7.4 (servability predicate, ACL Merkle proof at height). Mechanism: ACL
writes go to EVM storage via `StateDB.SetState` — journaled (revert-correct,
nested-frame-safe), consensus state under the app state root, and free of the
stateful-precompile call counter, so FHE-heavy transactions never approach
the per-transaction cap on stateful precompile calls.

## 1. Storage account

All slots live in the storage of the precompile address itself
(`0x…0900`). No Cosmos module store, no keeper. Reads/writes use
`evm.StateDB.GetState/SetState` inside `Run` — the same journal that unwinds
ordinary contract storage on revert.

## 2. Slot scheme — Solidity-compatible mapping layout

We use exactly the layout the Solidity compiler would produce, so every
standard tool (eth_getProof / EIP-1186, debuggers, indexers) understands it
and the KMS proof format needs no custom Merkle code.

Declared as-if:

```solidity
uint256 layoutVersion;                                      // slot 0
mapping(bytes32 => bytes32) handleMeta;                     // base slot 1
mapping(bytes32 => mapping(address => uint256)) acl;        // base slot 2
```

Slot derivation (standard Solidity rules):

- `layoutVersion` — slot `0`, value `1`.
- `handleMeta[h]` — slot `keccak256(h ‖ uint256(1))`.
- `acl[h][grantee]` — slot `keccak256(pad32(grantee) ‖ keccak256(h ‖ uint256(2)))`.

`‖` is byte concatenation; every key/base is 32 bytes.

## 3. Value encodings

**handleMeta[h]** — one packed word:

| bytes | field | meaning |
|---|---|---|
| 0–19 | `owner` | account that created `h` (see §5) |
| 20 | `ktype` | plaintext type tag: 0=ebool, 3=euint8 … 6=euint64 (log2 width / 8-coded; exact enum in types.go) |
| 21 | `flags` | bit0 = exists |
| 22–31 | reserved | zero |

**acl[h][grantee]** — permission bitmask (uint256, low bits):

| bit | permission (ABI.md `perm`) |
|---|---|
| 0 | `compute` (perm=0) |
| 1 | `reencryptToSelf` (perm=1) |
| 2 | `reveal` (perm=2) |

Grants are additive (`slot |= bit`). Revocation is deliberately absent from
the frozen ABI; if the spec later adds it, it arrives with a layout-version
bump.

## 4. Write rules

1. **Registration** — every handle-creating op (`verifyInput`,
   `trivialEncrypt`, and each compute op's result handle) writes
   `handleMeta[h]` with `owner = caller`, its `ktype`, and `exists = 1`.
   Without registering computed handles, `allow` on a computed balance handle
   would be impossible and ConfidentialERC20 flows could not authorize their
   own results.
2. **`allow(h, addr, perm)`** — requires `handleMeta[h].exists == 1` and
   `caller == handleMeta[h].owner` (§3: "written only by the contract owning
   h"). Effect: `acl[h][addr] |= bit(perm)`. Rejects unknown perm values.
3. **Guards on KMS-gateway ops** (mirrors §7.4 servability):
   - `requestReencrypt(h, pk)` — caller is `owner` of `h`, or holds the
     `reencryptToSelf` grant.
   - `requestReveal(h)` — caller holds the `reveal` grant (no wildcard; §7.4
     rate-shaping).
4. All writes go through the EVM journal (`SetState`); a reverted outer call
   rolls back registrations and grants automatically. Nothing routes through
   `RunNativeAction` — the initial stub's event-only `allow` is replaced.

## 5. Ownership model (v1 scope)

`owner` = the direct caller that created the handle (EOA or contract). When
`TFHE.sol`/ConfidentialERC20 land, the owning *contract* is the caller, which
matches §3's owning-contract rule. Transfer of ownership is out of scope for
v1 (not in the frozen ABI).

## 6. Proof format (what the KMS read path and the fraud proof consume)

Standard **EIP-1186** storage proof against the block's state root:

1. account proof for `0x…0900` → yields its `storageRoot`;
2. storage proof for the derived slot (`acl[h][grantee]` and, when needed,
   `handleMeta[h]`) against that `storageRoot`.

The §7.4 fraud-proof tuple carries exactly these two proofs at the cited
height. Historical provability follows from state-root retention
(21d + margin, per §7.4).

## 7. Explicitly deferred

- Real input-proof (π_in) verification — `verifyInput` keeps its
  non-empty-proof stub check until the input-proof workstream lands.
- The KMS-side read path (resolving and verifying these proofs at a given
  height) — specified and reviewed separately; an audit-scope item.
- Deterministic op-stream emission for the coprocessor (`StateDB.AddLog`
  route) — part of the op-stream protocol freeze.
- Disclosure-grant registry entries (§7.4's third servability arm) — arrives
  with the KMS workstream.
