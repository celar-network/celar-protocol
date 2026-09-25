//! The handoff format, pinned.
//!
//! This is the contract between the coprocessor and whatever submits for it.
//! A golden string rather than a round-trip: a round-trip through this crate's
//! own writer and reader would agree with itself no matter what it emitted,
//! and the reader that matters is in another language.

use celar_coprocessor::attest::Attestation;
use celar_coprocessor::emit::to_json;
use celar_coprocessor::ingest::StreamRef;

fn sample() -> Attestation {
    Attestation {
        at: StreamRef { height: 5, tx_index: 1, log_index: 2 },
        result_handle: [0xab; 32],
        ct_digest: [0xcd; 32],
        env_version: 1,
        coprocessor_id: [0x11; 20],
        signature: vec![0x22; 65],
    }
}

#[test]
fn the_format_is_exactly_this() {
    let expected = format!(
        concat!(
            "{{\"attestations\":[{{\"height\":5,\"tx_index\":1,\"log_index\":2,",
            "\"result_handle\":\"{}\",\"ct_digest\":\"{}\",",
            "\"env_version\":1,\"coprocessor_id\":\"{}\",\"signature\":\"{}\"}}]}}"
        ),
        "ab".repeat(32),
        "cd".repeat(32),
        "11".repeat(20),
        "22".repeat(65),
    );

    assert_eq!(to_json(&[sample()]), expected);
}

#[test]
fn hex_carries_no_prefix_and_is_lowercase() {
    // Both sides have to agree on this and neither would notice disagreeing:
    // a 0x-prefixed field parses as hex on one side and as a malformed byte
    // string on the other, and the failure surfaces as a rejected submission
    // nowhere near its cause.
    let out = to_json(&[sample()]);
    assert!(!out.contains("0x"), "no 0x prefixes: {out}");
    assert!(!out.chars().any(|c| c.is_ascii_uppercase() && c.is_ascii_hexdigit()), "lowercase only");
}

#[test]
fn an_empty_batch_is_still_a_document() {
    // A poll that executed nothing is a legitimate outcome, and the submitter
    // must be able to tell "nothing to do" from "the file is broken".
    assert_eq!(to_json(&[]), "{\"attestations\":[]}");
}
