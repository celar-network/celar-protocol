//! Field packing for protocol preimages.
//!
//! One module owns this because the rule binds any preimage, not one hash.
//! The signature and the re-randomization seed both hash the chain id and the
//! stream position, and a second packing of either would be the drift the
//! pinned encoding exists to prevent - silently, in the seed's case, since a
//! divergent seed yields a different ciphertext and therefore a different
//! attested digest rather than a rejected signature.
//!
//! These are crate-private on purpose: a caller outside this crate that needed
//! them would be a third implementation waiting to happen.

use crate::ingest::StreamRef;

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
pub(crate) fn chain_id_bytes(chain_id: u64) -> [u8; 8] {
    chain_id.to_be_bytes()
}

/// Same rule as chain_id_bytes, same section.
///
/// Height, then transaction index, then log index, big-endian, packed. This
/// matches the order the canonical ordering already sorts by, which is the
/// only argument in its favour.
pub(crate) fn stream_ref_bytes(at: &StreamRef) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&at.height.to_be_bytes());
    out[8..12].copy_from_slice(&at.tx_index.to_be_bytes());
    out[12..].copy_from_slice(&at.log_index.to_be_bytes());
    out
}

