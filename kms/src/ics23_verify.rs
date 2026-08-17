//! ICS23 verification path — the G10 finding made real (2026-08-15).
//!
//! `cosmos/evm` v0.7.0 `eth_getProof` does NOT return Ethereum MPT nodes.
//! Each proof entry is a protobuf-encoded `ics23.CommitmentProof`, and each
//! storage slot gets exactly two layers (rpc/backend/account_info.go →
//! `QueryClient.GetProof(clientCtx, "evm", StateKey(addr, slot))`):
//!
//!   layer 0  IAVL (non)existence of key `0x02 ‖ address ‖ slot` under the
//!            `evm` module store root                    (spec: iavl)
//!   layer 1  existence of store `"evm"` → store root under the root
//!            multistore commitment = Tendermint AppHash (spec: tendermint)
//!
//! The trusted root is therefore the **AppHash from a CometBFT header**, not
//! the EVM RPC's `stateRoot` (and `storageHash` is hardcoded to zero
//! upstream). Height offset: `AppHash` in the header at height N commits the
//! state *after executing block N−1* — proofs fetched at EVM block H verify
//! against the header at height **H+1**.
//!
//! Store layout constants confirmed against cosmos/evm v0.7.0
//! `x/vm/types/key.go` (ModuleName "evm", prefixStorage = 2, `StateKey` =
//! prefix ‖ addr ‖ slot).

use anyhow::{bail, Context, Result};
use ics23::{commitment_proof::Proof, CommitmentProof, HostFunctionsManager};
use prost::Message;

use crate::mpt::storage_word;

/// The Cosmos store the EVM state lives in (x/vm `StoreKey`).
pub const EVM_STORE_NAME: &[u8] = b"evm";

/// x/vm `KeyPrefixStorage`.
const PREFIX_STORAGE: u8 = 0x02;

/// Result of verifying one storage slot.
#[derive(Debug, PartialEq, Eq)]
pub enum SlotOutcome {
    /// Slot proven present; padded 32-byte value.
    Present([u8; 32]),
    /// Slot proven absent (x/vm deletes zero-valued slots).
    Absent,
}

/// IAVL key for an EVM storage slot: `0x02 ‖ address(20) ‖ slot(32)`.
pub fn state_key(address: &[u8; 20], slot: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 20 + 32);
    k.push(PREFIX_STORAGE);
    k.extend_from_slice(address);
    k.extend_from_slice(slot);
    k
}

/// Cheap format discriminator. MPT nodes are RLP lists (first byte ≥ 0xc0);
/// a protobuf `CommitmentProof` opens with a small field tag: 0x0a exist,
/// 0x12 nonexist, 0x1a batch, 0x22 compressed.
pub fn looks_like_ics23(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x0a | 0x12 | 0x1a | 0x22))
}

/// Verify one storage slot against the AppHash through both ICS23 layers.
///
/// `proof_bytes` are the raw (hex-decoded) entries of one `storageProof[i].proof`
/// array, in RPC order: `[iavl, multistore]`.
pub fn verify_slot(
    app_hash: &[u8; 32],
    address: &[u8; 20],
    slot: &[u8; 32],
    proof_bytes: &[Vec<u8>],
) -> Result<SlotOutcome> {
    if proof_bytes.len() != 2 {
        bail!(
            "expected 2 ics23 layers (iavl + multistore), got {}",
            proof_bytes.len()
        );
    }
    let iavl = CommitmentProof::decode(proof_bytes[0].as_slice())
        .context("decoding layer 0 as ics23 CommitmentProof (iavl)")?;
    let multistore = CommitmentProof::decode(proof_bytes[1].as_slice())
        .context("decoding layer 1 as ics23 CommitmentProof (multistore)")?;
    let key = state_key(address, slot);

    // Layer 0: (non)existence under the evm store root. The store root is
    // recomputed from the proof itself and only becomes trustworthy once
    // layer 1 links it to the AppHash.
    let (store_root, outcome) = match iavl.proof.as_ref().context("empty iavl CommitmentProof")? {
        Proof::Exist(e) => {
            if e.key != key {
                bail!(
                    "iavl existence proof is for key 0x{}, expected 0x{}",
                    hex::encode(&e.key),
                    hex::encode(&key)
                );
            }
            let root = ics23::calculate_existence_root::<HostFunctionsManager>(e)
                .map_err(|err| anyhow::anyhow!("calculating iavl root: {err:?}"))?;
            if !ics23::verify_membership::<HostFunctionsManager>(
                &iavl,
                &ics23::iavl_spec(),
                &root,
                &key,
                &e.value,
            ) {
                bail!("iavl membership verification failed for slot 0x{}", hex::encode(slot));
            }
            (root, SlotOutcome::Present(storage_word(&e.value)?))
        }
        Proof::Nonexist(ne) => {
            let left_root = ne
                .left
                .as_ref()
                .map(ics23::calculate_existence_root::<HostFunctionsManager>)
                .transpose()
                .map_err(|err| anyhow::anyhow!("calculating left-neighbor root: {err:?}"))?;
            let right_root = ne
                .right
                .as_ref()
                .map(ics23::calculate_existence_root::<HostFunctionsManager>)
                .transpose()
                .map_err(|err| anyhow::anyhow!("calculating right-neighbor root: {err:?}"))?;
            let root = match (left_root, right_root) {
                (Some(l), Some(r)) => {
                    if l != r {
                        bail!("nonexistence neighbors disagree on the store root");
                    }
                    l
                }
                (Some(l), None) => l,
                (None, Some(r)) => r,
                (None, None) => bail!("nonexistence proof has neither neighbor"),
            };
            if !ics23::verify_non_membership::<HostFunctionsManager>(
                &iavl,
                &ics23::iavl_spec(),
                &root,
                &key,
            ) {
                bail!(
                    "iavl non-membership verification failed for slot 0x{}",
                    hex::encode(slot)
                );
            }
            (root, SlotOutcome::Absent)
        }
        _ => bail!("unsupported ics23 proof shape in layer 0 (batch/compressed)"),
    };

    // Layer 1: the evm store root must be committed under the AppHash. The
    // store entry always exists on a running chain.
    match multistore
        .proof
        .as_ref()
        .context("empty multistore CommitmentProof")?
    {
        Proof::Exist(e) => {
            if e.key != EVM_STORE_NAME {
                bail!(
                    "multistore proof is for store {:?}, expected \"evm\"",
                    String::from_utf8_lossy(&e.key)
                );
            }
        }
        _ => bail!("multistore layer is not an existence proof"),
    }
    if !ics23::verify_membership::<HostFunctionsManager>(
        &multistore,
        &ics23::tendermint_spec(),
        &app_hash.to_vec(),
        EVM_STORE_NAME,
        &store_root,
    ) {
        bail!(
            "multistore verification failed: evm store root 0x{} is not \
             committed under AppHash 0x{} — wrong header height? (proofs at \
             EVM block H verify against the header at H+1)",
            hex::encode(&store_root),
            hex::encode(app_hash)
        );
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_key_layout() {
        let addr = [0xAA; 20];
        let slot = [0xBB; 32];
        let k = state_key(&addr, &slot);
        assert_eq!(k.len(), 53);
        assert_eq!(k[0], 0x02);
        assert_eq!(&k[1..21], &addr);
        assert_eq!(&k[21..], &slot);
    }

    #[test]
    fn format_discriminator() {
        // protobuf CommitmentProof shapes
        assert!(looks_like_ics23(&[0x0a, 0x01]));
        assert!(looks_like_ics23(&[0x12, 0x01]));
        // RLP list headers (MPT nodes)
        assert!(!looks_like_ics23(&[0xf8, 0x51]));
        assert!(!looks_like_ics23(&[0xe2, 0x10]));
        assert!(!looks_like_ics23(&[]));
    }

    #[test]
    fn rejects_wrong_layer_count() {
        let e = verify_slot(&[0u8; 32], &[0u8; 20], &[0u8; 32], &[vec![0x0a]]);
        assert!(e.is_err());
    }

    /// End-to-end fixture test against real devnet bytes. Runs only when
    /// `testdata/proof.json` + `testdata/header.json` exist (see task notes:
    /// header must be the CometBFT header at proof height + 1).
    #[test]
    fn fixture_roundtrip() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata");
        let proof_path = dir.join("proof.json");
        let header_path = dir.join("header.json");
        if !proof_path.exists() || !header_path.exists() {
            eprintln!("fixture_roundtrip: testdata missing, skipping");
            return;
        }
        let proof: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(proof_path).unwrap()).unwrap();
        let proof = proof.get("result").cloned().unwrap_or(proof);
        let header: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(header_path).unwrap()).unwrap();
        let app_hash_hex = header["result"]["header"]["app_hash"]
            .as_str()
            .expect("header.json: no result.header.app_hash");
        let mut app_hash = [0u8; 32];
        app_hash.copy_from_slice(&hex::decode(app_hash_hex).unwrap());

        let addr_hex = proof["address"].as_str().unwrap();
        let mut address = [0u8; 20];
        address.copy_from_slice(&hex::decode(addr_hex.trim_start_matches("0x")).unwrap());

        for entry in proof["storageProof"].as_array().unwrap() {
            let key_hex = entry["key"].as_str().unwrap().trim_start_matches("0x");
            let padded = format!("{key_hex:0>64}");
            let mut slot = [0u8; 32];
            slot.copy_from_slice(&hex::decode(&padded).unwrap());
            let nodes: Vec<Vec<u8>> = entry["proof"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| hex::decode(s.as_str().unwrap().trim_start_matches("0x")).unwrap())
                .collect();
            let outcome = verify_slot(&app_hash, &address, &slot, &nodes)
                .unwrap_or_else(|e| panic!("slot 0x{padded}: {e:#}"));
            eprintln!("fixture slot 0x{padded}: {outcome:?}");
        }
    }
}
