//! Celar ACL semantics over proven storage words — the KMS side of G10.
//!
//! Slot derivation and word layout mirror the on-chain source of truth,
//! `chain/celard/precompiles/fhe/{storage.go,STORAGE-LAYOUT.md}` (G9):
//!
//!   handleMeta[h]   at keccak256(h ‖ uint256(1)) → owner(20) ‖ ktype(1) ‖ flags(1)
//!   acl[h][grantee] at keccak256(pad32(grantee) ‖ keccak256(h ‖ uint256(2)))
//!                   → permission bits in the low-order byte
//!
//! The committee only ever acts on values PROVEN against a state root — that
//! is the entire point: servability is decided by cryptography, not by trust
//! in whoever relayed the request.

use anyhow::{bail, Result};
use serde::Serialize;

use crate::mpt::keccak256;

pub const PERM_BIT_COMPUTE: u8 = 0x01;
pub const PERM_BIT_REENCRYPT_TO_SELF: u8 = 0x02;
pub const PERM_BIT_REVEAL: u8 = 0x04;

/// The Celar FHE precompile account (chain-side constant).
pub const FHE_PRECOMPILE_ADDRESS: [u8; 20] = {
    let mut a = [0u8; 20];
    a[18] = 0x09;
    a
};

fn base_slot(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[31] = n;
    b
}

/// Slot of handleMeta[h]: keccak256(h ‖ uint256(1)).
pub fn meta_slot(handle: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(handle);
    buf[32..].copy_from_slice(&base_slot(1));
    keccak256(&buf)
}

/// Slot of acl[h][grantee]: keccak256(pad32(grantee) ‖ keccak256(h ‖ uint256(2))).
pub fn acl_slot(handle: &[u8; 32], grantee: &[u8; 20]) -> [u8; 32] {
    let mut inner_buf = [0u8; 64];
    inner_buf[..32].copy_from_slice(handle);
    inner_buf[32..].copy_from_slice(&base_slot(2));
    let inner = keccak256(&inner_buf);

    let mut outer = [0u8; 64];
    outer[12..32].copy_from_slice(grantee);
    outer[32..].copy_from_slice(&inner);
    keccak256(&outer)
}

/// Decoded handleMeta word.
#[derive(Debug, Clone, Serialize)]
pub struct HandleMeta {
    pub owner: String, // 0x-hex, 20 bytes
    pub ktype: u8,
    pub exists: bool,
}

pub fn decode_meta(word: &[u8; 32]) -> HandleMeta {
    HandleMeta {
        owner: format!("0x{}", hex::encode(&word[..20])),
        ktype: word[20],
        exists: word[21] & 0x01 == 1,
    }
}

/// Check a proven acl word for a permission bit.
pub fn has_perm(word: &[u8; 32], bit: u8) -> bool {
    word[31] & bit != 0
}

/// Map the CLI/ABI permission names to storage bits.
pub fn perm_bit(name: &str) -> Result<u8> {
    Ok(match name {
        "compute" => PERM_BIT_COMPUTE,
        "reencrypt-to-self" | "reencryptToSelf" => PERM_BIT_REENCRYPT_TO_SELF,
        "reveal" => PERM_BIT_REVEAL,
        other => bail!("unknown permission {other:?} (compute | reencrypt-to-self | reveal)"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompile_address_is_0x900() {
        assert_eq!(
            hex::encode(FHE_PRECOMPILE_ADDRESS),
            "0000000000000000000000000000000000000900"
        );
    }

    #[test]
    fn meta_word_decoding() {
        let mut w = [0u8; 32];
        w[..20].copy_from_slice(&[0xAA; 20]);
        w[20] = 6; // ktype
        w[21] = 0x01; // exists
        let m = decode_meta(&w);
        assert!(m.exists);
        assert_eq!(m.ktype, 6);
        assert_eq!(m.owner, format!("0x{}", "aa".repeat(20)));

        let empty = decode_meta(&[0u8; 32]);
        assert!(!empty.exists);
    }

    #[test]
    fn perm_bits() {
        let mut w = [0u8; 32];
        w[31] = PERM_BIT_REENCRYPT_TO_SELF;
        assert!(has_perm(&w, PERM_BIT_REENCRYPT_TO_SELF));
        assert!(!has_perm(&w, PERM_BIT_REVEAL));
        assert!(perm_bit("reveal").unwrap() == PERM_BIT_REVEAL);
        assert!(perm_bit("bogus").is_err());
    }

    #[test]
    fn slots_differ_per_grantee_and_handle() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let a = [3u8; 20];
        let b = [4u8; 20];
        assert_ne!(acl_slot(&h1, &a), acl_slot(&h1, &b));
        assert_ne!(acl_slot(&h1, &a), acl_slot(&h2, &a));
        assert_ne!(meta_slot(&h1), meta_slot(&h2));
        assert_ne!(meta_slot(&h1), acl_slot(&h1, &a));
    }
}
