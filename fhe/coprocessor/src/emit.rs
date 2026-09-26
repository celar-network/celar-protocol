//! Writing attestations out, for something else to submit.
//!
//! The loop decides what is true; getting it into chain state needs a
//! transaction, a funded key and a nonce, none of which belongs here. So the
//! two halves meet at a file.
//!
//! # Why a file and not a socket
//!
//! The same reasoning as the cross-language test vectors: the format is
//! written down, both sides read it, and neither side's code is the
//! definition. Two encoding disagreements have already been caught that way -
//! the endorsement digest's HTML escaping and the attestation preimage's field
//! packing - and both would have been silent in production.
//!
//! Every byte string is hex WITHOUT a 0x prefix, lowercase. Stated here
//! because it is the kind of detail each side would otherwise assume
//! differently and discover on a rejected submission.

use crate::attest::Attestation;

/// Serialise a batch as the handoff format.
pub fn to_json(attestations: &[Attestation]) -> String {
    let items: Vec<String> = attestations.iter().map(one).collect();
    format!("{{\"attestations\":[{}]}}", items.join(","))
}

fn one(a: &Attestation) -> String {
    format!(
        concat!(
            "{{\"height\":{},\"tx_index\":{},\"log_index\":{},",
            "\"result_handle\":\"{}\",\"ct_digest\":\"{}\",",
            "\"env_version\":{},\"coprocessor_id\":\"{}\",\"signature\":\"{}\"}}"
        ),
        a.at.height,
        a.at.tx_index,
        a.at.log_index,
        hex(&a.result_handle),
        hex(&a.ct_digest),
        a.env_version,
        hex(&a.coprocessor_id),
        hex(&a.signature),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
