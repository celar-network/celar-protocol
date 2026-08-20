//! Determinism of the compute path.
//! 
//! The fraud game requires that re-executing an operation reproduces the result
//! bit-for-bit: a verifier who recomputes a disputed operation must
//! be able to distinguish fraud from an honest difference and any
//! non-determinism destroys that
//! 
//! Encryption itself is randomised by design, so what must be reproducible 
//! is COMPUTATION over identical input ciphertext, not encyption.

use celar_zama::backend::Backend;
use celar_zama::dev_keys;
use tfhe::set_server_key;

fn setup() -> (Backend, tfhe::ClientKey) {
    let(ck, sk) = dev_keys();
    set_server_key(sk);
    (Backend::new(),ck)
}

#[test]
fn encryption_is_randomized_as_it_must_be() {
    // Guard aginst a false sense of secutiry: of two encrytions of the 
    // same value were identical, the scheme would be deterministic and
    // therefore broken
    let (mut be, ck) = setup();
    let a = be.encrypt(42, 64, &ck).unwrap();
    let b= be.encrypt(42, 64, &ck).unwrap();
    assert_ne!(
        be.serialize_handle(a).unwrap(),
        be.serialize_handle(b).unwrap(),
        "two encryption fo the same value must differ"
    );
}

#[test]
fn computation_is_reproducible_within_a_build() {
   let (mut be, ck) = setup();

    // one pair of operands, serialised so the exact same ciphertext can be
    // fed to every repetition
    let a0 = be.encrypt(1_000_000, 64, &ck).unwrap();
    let b0 = be.encrypt(337, 64, &ck).unwrap();
    let a_bytes = be.serialize_handle(a0).unwrap();
    let b_bytes = be.serialize_handle(b0).unwrap();

    let mut first: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = None;

    for round in 0..3 {
        let a = be.verify_input(&a_bytes, b"p").unwrap();
        let b = be.verify_input(&b_bytes, b"p").unwrap();

        let h_sum = be.add(a, b).unwrap();
        let sum = be.serialize_handle(h_sum).unwrap();
        let h_dif = be.sub(a, b).unwrap();
        let dif = be.serialize_handle(h_dif).unwrap();
        let cmp = be.le(a, b).unwrap();
        let h_sel = be.select(cmp, a, b).unwrap();
        let sel = be.serialize_handle(h_sel).unwrap();

        match &first {
            None => first = Some((sum, dif, sel)),
            Some((s0, d0, l0)) => {
                assert_eq!(*s0, sum, "add diverged on round {round}");
                assert_eq!(*d0, dif, "sub diverged on round {round}");
                assert_eq!(*l0, sel, "select diverged on round {round}");
            }
        }
    }
}

/// Emit a fingerprint of computed ciphertext for cross-build comparison>
/// Run with: cargo test --release --test determinism -- --nocapture fingerprint
#[test]
fn fingerprint() {
    use sha2::{Digest, Sha256};
    let (mut be, ck) = setup();

    // A FIXED input ciphertext is required for cross-build comparison, so 
    // build operands from trivival encryption: it is determinstic, whereas
    // real encryption is randomised. This tests the compute path, which is
    // what the fraud game re-excutes.
    let a = be.trivial_encrypt(1_000_000, 64).unwrap();
    let b = be.trivial_encrypt(337, 64).unwrap();

    let digest = |be: &Backend, h| {
        let mut hasher = Sha256::new();
        hasher.update(be.serialize_handle(h).unwrap());
        format!("{:x}", hasher.finalize())
    };

    let sum = be.add(a,b).unwrap();
    let dif = be.sub(a,b).unwrap();
    let cmp = be.le(a,b).unwrap();
    let sel = be.select(cmp, a, b).unwrap();

    println!("FINGERPRINT add    {}", digest(&be, sum));
    println!("FINGERPRINT sub    {}", digest(&be, dif));
    println!("FINGERPRINT select {}", digest(&be, sel));
    let _ = ck;
}

#[test]
fn digest_basis_excludes_the_wrapper() {
    let be = backend();                       // match the file's helper
    let h = be.trivial_encrypt(42, 64).unwrap();

    let wire = be.serialize_handle(h).unwrap();
    let basis = be.digest_basis(h).unwrap();

    // The wrapper carries id, tag and re-randomization metadata on top
    // of the radix ciphertext, so the digest basis must be strictly
    // smaller. If these ever match, the exclusion silently stopped
    // working and the attestation is back on application-settable bytes.
    assert!(
        basis.len() < wire.len(),
        "digest basis ({} bytes) is not smaller than the wire form ({}) \
         — wrapper fields may no longer be excluded",
        basis.len(), wire.len()
    );

    // Same value, same basis — twice.
    let again = be.digest_basis(h).unwrap();
    assert_eq!(basis, again, "digest basis is not stable");
}

#[test]
fn digest_basis_excludes_the_wrapper() {
    // Protocol v0.4 defines ctDigest over the integer-domain
    // ciphertext, excluding the high-level wrapper's id, tag and
    // re-randomization metadata. Those last two are settable by the
    // application and serialised with the ciphertext, so a digest
    // over the wrapper would let two honest coprocessors disagree
    // from identical computation — a difference the fraud game
    // cannot tell apart from cheating.
    let (mut be, ck) = setup();
    let h = be.encrypt(42, 64, &ck).unwrap();

    let wire = be.serialize_handle(h).unwrap();
    let basis = be.digest_basis(h).unwrap();

    // The wire form carries the wrapper on top of the radix
    // ciphertext, so the digest basis must be strictly smaller.
    // If these ever match, the exclusion has silently stopped
    // working and attestation is back on application-settable bytes.
    assert!(
        basis.len() < wire.len(),
        "digest basis ({} B) is not smaller than the wire form ({} B) \
         — wrapper fields may no longer be excluded",
        basis.len(),
        wire.len()
    );

    // Same ciphertext, same basis, twice.
    assert_eq!(
        basis,
        be.digest_basis(h).unwrap(),
        "digest basis is not stable across calls"
    );
}