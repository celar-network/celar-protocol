//! No golden vector here, deliberately.
//!
//! The decoder's tests pin hex derived from the frozen schema table, which is
//! authoritative. The attestation preimage has no such table: the byte
//! encodings of the chain id and the stream reference are unspecified. Pinning
//! a hash of our own packing would look like a specification-derived vector
//! while being nothing of the kind - false authority, and the exact mistake
//! that makes an encoder agree only with itself.
//!
//! So these test properties that hold under ANY encoding: determinism, and
//! that every field actually reaches the hash. When the encoding is pinned,
//! a golden vector belongs here and these stay.

use celar_coprocessor::attest::signing_preimage;
use celar_coprocessor::ingest::StreamRef;

fn at(h: u64, tx: u32, log: u32) -> StreamRef {
    StreamRef { height: h, tx_index: tx, log_index: log }
}

#[test]
fn is_deterministic() {
    let a = signing_preimage(9, &at(1, 2, 3), &[7u8; 32], &[8u8; 32]);
    let b = signing_preimage(9, &at(1, 2, 3), &[7u8; 32], &[8u8; 32]);
    assert_eq!(a, b);
}

/// Every input must reach the hash. A field silently dropped from a preimage
/// is a signature that binds less than it claims - and it would never show up
/// as a failure, only as an attestation that verifies when it should not.
#[test]
fn every_field_changes_the_preimage() {
    let base = signing_preimage(9, &at(1, 2, 3), &[7u8; 32], &[8u8; 32]);
    let cases = [
        ("chain id", signing_preimage(10, &at(1, 2, 3), &[7u8; 32], &[8u8; 32])),
        ("height", signing_preimage(9, &at(2, 2, 3), &[7u8; 32], &[8u8; 32])),
        ("tx index", signing_preimage(9, &at(1, 3, 3), &[7u8; 32], &[8u8; 32])),
        ("log index", signing_preimage(9, &at(1, 2, 4), &[7u8; 32], &[8u8; 32])),
        ("result handle", signing_preimage(9, &at(1, 2, 3), &[6u8; 32], &[8u8; 32])),
        ("ct digest", signing_preimage(9, &at(1, 2, 3), &[7u8; 32], &[9u8; 32])),
    ];
    for (field, other) in cases {
        assert_ne!(base, other, "{field} does not reach the signed preimage");
    }
}

/// Distinct positions must not collide through the packing. Height 1 with log
/// index 0 and height 0 with a large log index must differ, or a
/// concatenation has become ambiguous.
#[test]
fn positions_do_not_alias_through_the_packing() {
    let a = signing_preimage(1, &at(1, 0, 0), &[0u8; 32], &[0u8; 32]);
    let b = signing_preimage(1, &at(0, 1, 0), &[0u8; 32], &[0u8; 32]);
    let c = signing_preimage(1, &at(0, 0, 1), &[0u8; 32], &[0u8; 32]);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}
