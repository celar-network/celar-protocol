//! The seed's own properties, and the one that matters: it moves with the
//! attestation preimage, because both are built from the same packing.

use celar_coprocessor::attest::signing_preimage;
use celar_coprocessor::ingest::StreamRef;
use celar_coprocessor::rerand::seed;

fn at(h: u64, tx: u32, log: u32) -> StreamRef {
    StreamRef { height: h, tx_index: tx, log_index: log }
}

#[test]
fn is_deterministic() {
    let a = seed(9, &at(1, 2, 3), &[7u8; 32]);
    let b = seed(9, &at(1, 2, 3), &[7u8; 32]);
    assert_eq!(a, b, "derived randomness must be derived, not sampled");
}

#[test]
fn every_field_reaches_the_seed() {
    let base = seed(9, &at(1, 2, 3), &[7u8; 32]);
    for (field, other) in [
        ("chain id", seed(10, &at(1, 2, 3), &[7u8; 32])),
        ("height", seed(9, &at(2, 2, 3), &[7u8; 32])),
        ("tx index", seed(9, &at(1, 3, 3), &[7u8; 32])),
        ("log index", seed(9, &at(1, 2, 4), &[7u8; 32])),
        ("result handle", seed(9, &at(1, 2, 3), &[6u8; 32])),
    ] {
        assert_ne!(base, other, "{field} does not reach the seed");
    }
}

/// Identical work at DIFFERENT stream positions must seed differently - that
/// is the whole property, and the reason the position is in the preimage at
/// all. Two executions of the same operation at one position must seed the
/// same, or sampled re-execution cannot separate honest agreement from fraud.
#[test]
fn position_separates_otherwise_identical_work() {
    let here = seed(1, &at(100, 0, 0), &[5u8; 32]);
    let there = seed(1, &at(100, 0, 1), &[5u8; 32]);
    assert_ne!(here, there, "same work at two positions produced one seed");
}

/// The property the shared packing exists to guarantee.
///
/// The seed and the attestation preimage are different hashes with different
/// domains, but they are built from the same packed fields. If someone ever
/// re-packs one of them, this diverges: a field that moves one must move the
/// other. A signature mismatch announces itself; a seed mismatch does not -
/// it yields a different ciphertext and therefore a different attested digest,
/// which the fraud game reads as dishonesty.
#[test]
fn the_seed_and_the_signing_preimage_move_together() {
    let handle = [7u8; 32];
    let digest = [8u8; 32];

    for (field, s2, p2) in [
        ("chain id",
         seed(10, &at(1, 2, 3), &handle),
         signing_preimage(10, &at(1, 2, 3), &handle, &digest)),
        ("height",
         seed(9, &at(2, 2, 3), &handle),
         signing_preimage(9, &at(2, 2, 3), &handle, &digest)),
        ("log index",
         seed(9, &at(1, 2, 4), &handle),
         signing_preimage(9, &at(1, 2, 4), &handle, &digest)),
    ] {
        let s1 = seed(9, &at(1, 2, 3), &handle);
        let p1 = signing_preimage(9, &at(1, 2, 3), &handle, &digest);
        assert_ne!(s1, s2, "{field} did not change the seed");
        assert_ne!(p1, p2, "{field} did not change the signing preimage");
    }
}

/// They must not be the SAME hash either. Same fields, different domains -
/// if the domain separator were ever dropped, one could be replayed as the
/// other.
#[test]
fn the_two_derivations_are_domain_separated() {
    let handle = [7u8; 32];
    assert_ne!(
        seed(9, &at(1, 2, 3), &handle),
        signing_preimage(9, &at(1, 2, 3), &handle, &[0u8; 32]),
        "seed and signing preimage collided; the domain separator is doing nothing"
    );
}
