//! Deterministic re-randomization.
//!
//! The protocol derives the randomness rather than sampling it, so that two
//! honest executions of the same operation are bit-identical. Fresh randomness
//! would make honest divergence indistinguishable from fraud under sampled
//! re-execution - the contradiction the derived form was introduced to remove.
//!
//! What this property is, stated because it is easy to over-read: positional
//! uniqueness and format hygiene, NOT unlinkability. The mask is publicly
//! invertible by construction, and no security statement may cite
//! re-randomization as a confidentiality mechanism.
//!
//! Scope: evaluation side only. Client and input encryption randomness is
//! always client-fresh, since deterministic input encryption would break the
//! encryption scheme's own security.
//!
//! WHERE it applies is settled and is not this function's business: the
//! obligation falls on the evaluator performing a boundary crossing, and it
//! triggers on performing one rather than on observing one. This derives the
//! seed for whoever is performing it.

use sha3::{Digest, Keccak256};

use crate::ingest::StreamRef;
use crate::preimage::{chain_id_bytes, stream_ref_bytes};

/// Domain separator for the re-randomization seed.
pub const RERAND_DOMAIN: &str = "celar.rerand.v1";

/// The seed for one result's re-randomization.
///
/// Uses the same packing as the attestation preimage, by calling the same
/// functions rather than repeating them. That is the whole reason the packing
/// lives in one module: a divergence here does not announce itself the way a
/// rejected signature does - it produces a different seed, a different
/// ciphertext, and a different attested digest, which reads as fraud rather
/// than as a packing disagreement.
pub fn seed(chain_id: u64, at: &StreamRef, result_handle: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(RERAND_DOMAIN.as_bytes());
    h.update(chain_id_bytes(chain_id));
    h.update(stream_ref_bytes(at));
    h.update(result_handle);
    h.finalize().into()
}
