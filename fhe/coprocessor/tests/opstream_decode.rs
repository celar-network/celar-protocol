//! Golden vectors for §3's envelope.
//!
//! The bytes below are hand-derived from the frozen table, NOT produced by
//! either encoder. That is the whole point: the chain-side Go decoder is
//! checked against this same vector, so the two implementations are each
//! pinned to the specification rather than to each other. An encoder checked
//! against itself agrees with itself.

use celar_coprocessor::opstream::{decode, DecodeError, StreamEvent};

/// `select` (opcode 0x20), ebool result, three operands, hcu 3000, one aux byte.
///
///   01          version
///   20          opcode = select
///   00          resultType = ebool
///   03          operandCount
///   01*32       operand 0
///   02*32       operand 1
///   03*32       operand 2
///   04*32       resultHandle
///   00000bb8    hcuCost = 3000
///   0001        auxLen
///   40          aux
fn golden_hex() -> String {
    format!(
        "0120{}{}{}{}{}{}{}{}",
        "00", "03",
        "01".repeat(32),
        "02".repeat(32),
        "03".repeat(32),
        "04".repeat(32),
        "00000bb8",
        "000140",
    )
}

fn golden() -> Vec<u8> {
    hex::decode(golden_hex()).expect("golden vector is not valid hex")
}

#[test]
fn decodes_the_spec_derived_vector() {
    let e = decode(&golden()).expect("hand-derived vector must decode");
    assert_eq!(e.version, 0x01);
    assert_eq!(e.opcode, 0x20);
    assert_eq!(e.result_type, 0x00);
    assert_eq!(e.operands.len(), 3);
    assert_eq!(e.operands[0], [0x01; 32]);
    assert_eq!(e.operands[2], [0x03; 32]);
    assert_eq!(e.result_handle, [0x04; 32]);
    assert_eq!(e.hcu_cost, 3000);
    assert_eq!(e.aux, vec![0x40]);
}

/// §3 is explicit that this is a halt, not a skip: a consumer that ignores what
/// it cannot parse disagrees with the chain without saying so.
#[test]
fn unknown_version_halts() {
    let mut bad = golden();
    bad[0] = 0x02;
    assert_eq!(decode(&bad), Err(DecodeError::UnknownVersion(0x02)));
}

#[test]
fn refuses_more_operands_than_the_schema_allows() {
    let mut bad = golden();
    bad[3] = 4;
    assert_eq!(decode(&bad), Err(DecodeError::TooManyOperands(4)));
}

/// Every boundary, not just the first. A decoder that is strict about its
/// opening fields and loose about its last one fails in the place that is
/// hardest to attribute.
#[test]
fn truncation_at_any_boundary_is_refused() {
    let full = golden();
    for cut in 1..full.len() {
        assert!(
            decode(&full[..cut]).is_err(),
            "truncating to {cut} of {} bytes decoded anyway",
            full.len()
        );
    }
}

#[test]
fn aux_shorter_than_declared_is_refused() {
    let mut bad = golden();
    bad.pop(); // drop the single aux byte, leave auxLen claiming 1
    assert_eq!(
        decode(&bad),
        Err(DecodeError::AuxLengthMismatch { declared: 1, present: 0 })
    );
}

#[test]
fn trailing_bytes_are_refused() {
    let mut bad = golden();
    bad.push(0xFF);
    assert_eq!(decode(&bad), Err(DecodeError::TrailingBytes(1)));
}

/// Admission will carry `auxLen` 64 and, under a draft amendment, resultType
/// 0xFF. Neither is interpreted yet — but neither may be rejected by the
/// envelope decoder, or the consumer breaks on the day that amendment lands.
#[test]
fn carries_an_uninterpreted_result_type_and_a_64_byte_aux() {
    let hex = format!(
        "0101FF00{}{}{}{}",
        "04".repeat(32),
        "00000bb8",
        "0040",
        "aa".repeat(64),
    );
    let e = decode(&hex::decode(hex).unwrap()).expect("must decode");
    assert_eq!(e.result_type, 0xFF, "raw byte, not interpreted");
    assert_eq!(e.operands.len(), 0);
    assert_eq!(e.aux.len(), 64);
}
