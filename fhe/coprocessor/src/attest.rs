//! The result attestation.
//!
//! Per the protocol, a coprocessor produces one of these per evaluated op:
//! the stream position, the chain-assigned result handle, the ciphertext
//! digest, an envelope version, an identity and a signature.
//!
//! The envelope version exists so a future validity proof arrives as a new
//! version carrying a proof field, with the handle-to-digest binding
//! unchanged and no state migration. Nothing here may assume the current
//! shape is structural.

use sha3::{Digest, Keccak256};

use crate::ingest::StreamRef;
use crate::preimage::{chain_id_bytes, stream_ref_bytes};

/// Domain separator for the signed preimage.
pub const ATTEST_DOMAIN: &str = "celar.copro.attest.v1";

/// Digest plus bonded signature. A validity proof would be a later version.
pub const ENV_DIGEST_AND_SIGNATURE: u8 = 0x01;

/// The 32 bytes a coprocessor signs.
pub fn signing_preimage(
    chain_id: u64,
    at: &StreamRef,
    result_handle: &[u8; 32],
    ct_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(ATTEST_DOMAIN.as_bytes());
    h.update(chain_id_bytes(chain_id));
    h.update(stream_ref_bytes(at));
    h.update(result_handle);
    h.update(ct_digest);
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub at: StreamRef,
    pub result_handle: [u8; 32],
    pub ct_digest: [u8; 32],
    pub env_version: u8,
    pub coprocessor_id: [u8; 20],
    pub signature: Vec<u8>,
}
