//! Input admission and the KMS-facing stand-ins.

use celar_zama::backend::{Backend, FheError};
use celar_zama::dev_keys;
use tfhe::set_server_key;

const QUORUM: u32 = 79;

fn backend() -> (Backend, tfhe::ClientKey) {
    let (ck, sk) = dev_keys();
    set_server_key(sk);
    (Backend::new(), ck)
}

#[test]
fn client_ciphertext_round_trips_through_admission() {
    let (mut be, ck) = backend();

    // client encrypts and serialises, as a real submission would
    let local = be.encrypt(1_234_567, 64, &ck).unwrap();
    let wire = be.serialize_handle(local).unwrap();
    assert!(!wire.is_empty(), "serialised ciphertext must not be empty");

    // the backend admits it and it still decrypts to the same value
    let admitted = be.verify_input(&wire, b"proof-placeholder").unwrap();
    assert_eq!(be.threshold_decrypt(admitted, QUORUM, &ck).unwrap(), 1_234_567);

    // and it is usable in computation afterwards
    let doubled = be.add(admitted, admitted).unwrap();
    assert_eq!(be.oracle_uint(doubled, &ck).unwrap(), 2_469_134);
}

#[test]
fn admission_rejects_bad_submissions() {
    let (mut be, ck) = backend();
    let h = be.encrypt(42, 64, &ck).unwrap();
    let wire = be.serialize_handle(h).unwrap();

    assert_eq!(
        be.verify_input(&wire, b"").unwrap_err(),
        FheError::ProofRejected,
        "an empty proof must be refused"
    );
    assert_eq!(
        be.verify_input(b"not a ciphertext", b"proof").unwrap_err(),
        FheError::MalformedCiphertext,
        "malformed ciphertext must be refused"
    );
}

#[test]
fn reencryption_is_bound_to_the_recipient() {
    let (mut be, ck) = backend();
    let h = be.encrypt(7, 64, &ck).unwrap();

    let alice = be.threshold_reencrypt(h, QUORUM, b"alice-key", &ck).unwrap();
    let bob = be.threshold_reencrypt(h, QUORUM, b"bob-key", &ck).unwrap();
    assert_ne!(alice, bob, "material for one recipient must not serve another");

    let again = be.threshold_reencrypt(h, QUORUM, b"alice-key", &ck).unwrap();
    assert_eq!(alice, again, "must be deterministic for a given recipient");

    assert_eq!(
        be.threshold_reencrypt(h, QUORUM, b"", &ck).unwrap_err(),
        FheError::MissingRecipientKey,
        "re-encryption without a recipient key is meaningless"
    );
}
