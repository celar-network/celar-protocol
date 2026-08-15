//! Merkle-Patricia-Trie inclusion-proof verification (EIP-1186 / eth_getProof
//! node lists) — the G10 primitive.
//!
//! Standard, boring, and deliberately dependency-light: the ACL read path is
//! a named audit-scope item, so "small and standard" beats clever (onboarding
//! doc §4, G10 row). No custom Merkle format anywhere — this is exactly the
//! geth secure-trie layout, which is the point of the ACL living in EVM
//! storage (G9/S4 decision).

use std::collections::HashMap;

use anyhow::{bail, Result};
use sha3::{Digest, Keccak256};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

/// Outcome of walking a proof: the key is present with a value, or provably
/// absent. Anything malformed is an error — never conflate "absent" with
/// "invalid proof" (the servability predicate treats them very differently).
#[derive(Debug, PartialEq)]
pub enum ProofOutcome {
    Present(Vec<u8>),
    Absent,
}

/// Verify one MPT proof.
///
/// * `root` — the trie root the proof must chain up to (state root for the
///   account trie, the account's storage root for a storage trie).
/// * `hashed_key` — keccak256 of the address / storage slot (secure trie).
/// * `nodes` — the ordered node list from eth_getProof.
///
/// Returns the leaf's RLP-encoded value on inclusion.
pub fn verify_proof(
    root: &[u8; 32],
    hashed_key: &[u8; 32],
    nodes: &[Vec<u8>],
) -> Result<ProofOutcome> {
    // Node bodies indexed by their keccak — a proof is valid only if every
    // step's hash chains from the root.
    let mut db: HashMap<[u8; 32], &[u8]> = HashMap::new();
    for n in nodes {
        db.insert(keccak256(n), n.as_slice());
    }

    let nibbles: Vec<u8> = hashed_key
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0F])
        .collect();

    // What we expect next: either a 32-byte hash to resolve in `db`, or an
    // embedded (<32-byte) node's raw RLP.
    enum Next {
        Hash([u8; 32]),
        Embedded(Vec<u8>),
        Value(Vec<u8>),
        Absent,
    }

    let mut cursor = Next::Hash(*root);
    let mut depth = 0usize;
    let mut owned_node: Vec<u8>;

    loop {
        let node_bytes: &[u8] = match cursor {
            Next::Hash(h) => match db.get(&h) {
                Some(n) => n,
                None => bail!(
                    "proof is missing the node for hash {} at depth {}",
                    hex::encode(h),
                    depth / 1
                ),
            },
            Next::Embedded(ref e) => {
                owned_node = e.clone();
                &owned_node
            }
            Next::Value(v) => return Ok(ProofOutcome::Present(v)),
            Next::Absent => return Ok(ProofOutcome::Absent),
        };

        let rlp = rlp::Rlp::new(node_bytes);
        match rlp.item_count()? {
            17 => {
                // Branch node.
                if depth == nibbles.len() {
                    let val = rlp.at(16)?;
                    cursor = if val.is_empty() {
                        Next::Absent
                    } else {
                        Next::Value(val.data()?.to_vec())
                    };
                    continue;
                }
                let child = rlp.at(nibbles[depth] as usize)?;
                depth += 1;
                cursor = child_cursor(&child)?;
            }
            2 => {
                // Extension or leaf; item 0 is the hex-prefix-encoded path.
                let (path, is_leaf) = decode_hp(rlp.at(0)?.data()?)?;
                let remaining = &nibbles[depth..];
                if is_leaf {
                    cursor = if remaining == path.as_slice() {
                        Next::Value(rlp.at(1)?.data()?.to_vec())
                    } else {
                        Next::Absent
                    };
                } else {
                    if remaining.len() < path.len() || remaining[..path.len()] != path[..] {
                        cursor = Next::Absent;
                        continue;
                    }
                    depth += path.len();
                    cursor = child_cursor(&rlp.at(1)?)?;
                }
            }
            n => bail!("malformed trie node with {n} items at depth {depth}"),
        }

        // helper: interpret a branch/extension child slot
        fn child_cursor(child: &rlp::Rlp) -> Result<Next> {
            if child.is_empty() && child.is_data() {
                return Ok(Next::Absent);
            }
            if child.is_data() {
                let d = child.data()?;
                if d.len() == 32 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(d);
                    return Ok(Next::Hash(h));
                }
                bail!("child reference with unexpected length {}", d.len());
            }
            // Embedded node (total encoding < 32 bytes).
            Ok(Next::Embedded(child.as_raw().to_vec()))
        }
    }
}

/// Decode a hex-prefix-encoded path. Returns (nibbles, is_leaf).
fn decode_hp(encoded: &[u8]) -> Result<(Vec<u8>, bool)> {
    if encoded.is_empty() {
        bail!("empty hex-prefix path");
    }
    let flag = encoded[0] >> 4;
    let is_leaf = flag >= 2;
    let odd = flag & 1 == 1;
    let mut nibbles = Vec::with_capacity(encoded.len() * 2);
    if odd {
        nibbles.push(encoded[0] & 0x0F);
    }
    for b in &encoded[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0F);
    }
    Ok((nibbles, is_leaf))
}

/// Left-pad trie storage bytes back to the 32-byte EVM word (geth trims
/// leading zeroes before storing).
pub fn storage_word(value_bytes: &[u8]) -> Result<[u8; 32]> {
    if value_bytes.len() > 32 {
        bail!("storage value longer than 32 bytes");
    }
    let mut w = [0u8; 32];
    w[32 - value_bytes.len()..].copy_from_slice(value_bytes);
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hp_decoding() {
        // Examples from the yellow-paper appendix.
        assert_eq!(
            decode_hp(&[0x11, 0x23, 0x45]).unwrap(),
            (vec![1, 2, 3, 4, 5], false) // odd extension
        );
        assert_eq!(
            decode_hp(&[0x00, 0x01, 0x23]).unwrap(),
            (vec![0, 1, 2, 3], false) // even extension
        );
        assert_eq!(
            decode_hp(&[0x3f, 0x1c, 0xb8]).unwrap(),
            (vec![15, 1, 12, 11, 8], true) // odd leaf
        );
        assert_eq!(
            decode_hp(&[0x20, 0x0f, 0x1c, 0xb8]).unwrap(),
            (vec![0, 15, 1, 12, 11, 8], true) // even leaf
        );
    }

    #[test]
    fn single_leaf_trie_roundtrip() {
        // Build the smallest possible trie by hand: one leaf holding a value
        // under a known key, root = keccak(leaf). Verifies inclusion and
        // rejects a wrong root.
        let key = keccak256(b"celar-test-key");
        let nibbles: Vec<u8> = key.iter().flat_map(|b| [b >> 4, b & 0x0F]).collect();

        // HP-encode the full path as a leaf (even length → flag 0x20).
        let mut hp = vec![0x20];
        for pair in nibbles.chunks(2) {
            hp.push((pair[0] << 4) | pair[1]);
        }
        let value = b"celar-value".to_vec();

        let mut stream = rlp::RlpStream::new_list(2);
        stream.append(&hp).append(&value);
        let leaf = stream.out().to_vec();
        let root = keccak256(&leaf);

        let got = verify_proof(&root, &key, &[leaf.clone()]).unwrap();
        assert_eq!(got, ProofOutcome::Present(value));

        let wrong_root = keccak256(b"nope");
        assert!(verify_proof(&wrong_root, &key, &[leaf]).is_err());
    }

    #[test]
    fn storage_word_padding() {
        let w = storage_word(&[0x02]).unwrap();
        assert_eq!(w[31], 0x02);
        assert!(w[..31].iter().all(|b| *b == 0));
        assert!(storage_word(&[0u8; 33]).is_err());
    }
}
