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

/// Domain separator for the signed preimage.
pub const ATTEST_DOMAIN: &str = "celar.copro.attest.v1";

/// Digest plus bonded signature. A validity proof would be a later version.
pub const ENV_DIGEST_AND_SIGNATURE: u8 = 0x01;

/// Encoding fixed by the protocol: all integer fields in any preimage are
/// fixed-width big-endian, with no minimal encoding, no length prefixes and
/// no separators. See the schema section that pins it.
///
/// The protocol defines the signed preimage as a domain string concatenated
/// with the chain id, the stream reference, the result handle and the
/// ciphertext digest. The last two are 32 bytes each and unambiguous. The
/// first two have NO stated byte encoding.
///
/// A verifier that packs them differently computes a different preimage and
/// rejects every honest attestation, which is why this is specified rather
/// than chosen locally.
///
/// The rule is deliberately wider than this signature. The re-randomization
/// seed hashes the same two fields, and there a mismatch does not stick out
/// as a rejected attestation: it yields a different seed, a different
/// ciphertext, and therefore a different attested digest - which the
/// determinism obligations make consensus-critical. Anything deriving a
/// preimage from these fields MUST call these two functions rather than pack
/// them again.
fn chain_id_bytes(chain_id: u64) -> [u8; 8] {
    chain_id.to_be_bytes()
}

/// Same rule as chain_id_bytes, same section.
///
/// Height, then transaction index, then log index, big-endian, packed. This
/// matches the order the canonical ordering already sorts by, which is the
/// only argument in its favour.
fn stream_ref_bytes(at: &StreamRef) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&at.height.to_be_bytes());
    out[8..12].copy_from_slice(&at.tx_index.to_be_bytes());
    out[12..].copy_from_slice(&at.log_index.to_be_bytes());
    out
}

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
