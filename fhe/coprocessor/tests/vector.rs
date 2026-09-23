//! The producing side of the shared attestation vector.
//!
//! The consuming side reads the same file and asserts the same value. Neither
//! implementation vouches for itself: a digest computed here and checked only
//! against this crate would prove that the code is consistent with itself,
//! which is not the property at issue.

use celar_coprocessor::attest::signing_preimage;
use celar_coprocessor::ingest::StreamRef;

fn hex32(s: &str) -> [u8; 32] {
    let raw = hex::decode(s).expect("fixture field is not hex");
    assert_eq!(raw.len(), 32, "fixture field is not 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

#[test]
fn attestation_preimage_matches_the_shared_vector() {
    let raw = std::fs::read_to_string("../../testdata/attestation/vector.json")
        .expect("shared vector not found");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("vector is not json");
    let i = &v["input"];

    let at = StreamRef {
        height: i["height"].as_u64().unwrap(),
        tx_index: i["tx_index"].as_u64().unwrap() as u32,
        log_index: i["log_index"].as_u64().unwrap() as u32,
    };
    let got = hex::encode(signing_preimage(
        i["chain_id"].as_u64().unwrap(),
        &at,
        &hex32(i["result_handle"].as_str().unwrap()),
        &hex32(i["ct_digest"].as_str().unwrap()),
    ));

    let mine = v["preimage_keccak_coprocessor"].as_str().unwrap();
    if mine.is_empty() {
        panic!("vector has no recorded value for this side; this run computed {got}");
    }
    assert_eq!(got, mine, "this side drifted from the vector");

    // The point of the file: the other implementation's value must agree.
    let theirs = v["preimage_keccak_go"].as_str().unwrap();
    if !theirs.is_empty() {
        assert_eq!(
            got, theirs,
            "THE TWO IMPLEMENTATIONS DISAGREE — same inputs, different preimage"
        );
    }
}

/// The producing half of the signature fixture.
///
/// Agreement on the preimage says nothing about agreement on the signature's
/// encoding, its recovery id, or the low-s rule — all three are conventions
/// the two sides implement separately. This records what this side produces so
/// the consuming side can verify it.
#[test]
fn signature_over_the_shared_vector() {
    use celar_coprocessor::sign::{coprocessor_id, sign_attestation};
    use k256::ecdsa::SigningKey;

    let raw = std::fs::read_to_string("../../testdata/attestation/vector.json").unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let i = &v["input"];
    let sk = SigningKey::from_bytes(
        &hex32(v["signing"]["secret_key"].as_str().unwrap()).into(),
    )
    .unwrap();

    let at = StreamRef {
        height: i["height"].as_u64().unwrap(),
        tx_index: i["tx_index"].as_u64().unwrap() as u32,
        log_index: i["log_index"].as_u64().unwrap() as u32,
    };
    let a = sign_attestation(
        &sk,
        i["chain_id"].as_u64().unwrap(),
        &at,
        &hex32(i["result_handle"].as_str().unwrap()),
        &hex32(i["ct_digest"].as_str().unwrap()),
    );

    assert_eq!(a.signature.len(), 65, "signature must be r||s||v");
    assert!(a.signature[64] <= 1, "recovery id must be 0 or 1");
    assert_eq!(a.coprocessor_id, coprocessor_id(&sk));

    let sig = hex::encode(&a.signature);
    let id = hex::encode(a.coprocessor_id);
    let recorded_sig = v["signing"]["signature"].as_str().unwrap();
    if recorded_sig.is_empty() {
        panic!("vector has no recorded signature; this run produced\n  signature: {sig}\n  id: {id}");
    }
    assert_eq!(sig, recorded_sig, "this side's signature drifted from the vector");
    assert_eq!(id, v["signing"]["coprocessor_id"].as_str().unwrap());
}
