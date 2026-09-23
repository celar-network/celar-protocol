//! Signing an attestation.
//!
//! The chain REJECTS a high-s signature rather than normalising it, so this
//! side must produce the canonical form at signing time. A signer that emitted
//! the malleable encoding would have its attestations refused by a verifier
//! behaving exactly as specified — and from here that looks like a chain fault
//! rather than our own.

use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

use crate::attest::{signing_preimage, Attestation, ENV_DIGEST_AND_SIGNATURE};
use crate::ingest::StreamRef;

/// The identity a coprocessor is known by: the last twenty bytes of the hash
/// of its uncompressed public key, with the leading tag byte excluded.
///
/// There is no registry, by design — the identity IS the key. Which means a
/// key rotation is a new identity and a new bond, not a rotation in place.
pub fn coprocessor_id(key: &SigningKey) -> [u8; 20] {
    let point = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

/// Sign one executed operation.
///
/// Returns the attestation with its signature as 65 bytes, `r ‖ s ‖ v`, with
/// the recovery id as the final byte and `s` in its canonical low form.
pub fn sign_attestation(
    key: &SigningKey,
    chain_id: u64,
    at: &StreamRef,
    result_handle: &[u8; 32],
    ct_digest: &[u8; 32],
) -> Attestation {
    let preimage = signing_preimage(chain_id, at, result_handle, ct_digest);

    // k256 produces the low-s form; the recovery id is computed against it, so
    // the pair is consistent by construction rather than by a later fix-up.
    let (sig, recid) = key
        .sign_prehash_recoverable(&preimage)
        .expect("a 32-byte prehash is always signable");

    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&sig.to_bytes());
    signature.push(recid.to_byte());

    Attestation {
        at: at.clone(),
        result_handle: *result_handle,
        ct_digest: *ct_digest,
        env_version: ENV_DIGEST_AND_SIGNATURE,
        coprocessor_id: coprocessor_id(key),
        signature,
    }
}
