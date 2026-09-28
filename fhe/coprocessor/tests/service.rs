//! The loop, end to end against a fixture chain.
//!
//! Each half of this has had tests for weeks. What none of them could show is
//! whether the decoder's output is what the executor expects and whether the
//! position the signature commits to is the position the event arrived at —
//! questions that only exist once something drives one from the other.

use celar_coprocessor::attest::signing_preimage;
use celar_coprocessor::exec::op;
use celar_coprocessor::ingest::{RawEvent, StreamRef, StreamSource};
use celar_coprocessor::service::{DeferReason, Deferred, Service, ServiceError};
use celar_coprocessor::sign::coprocessor_id;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

const CHAIN_ID: u64 = 23529;

/// §3's envelope, built by hand from the schema rather than from the encoder.
///
/// Deliberate: an encoder-built fixture tests the decoder against its own
/// mirror image. These bytes answer to the document.
fn envelope(opcode: u8, operands: &[[u8; 32]], result_handle: [u8; 32], aux: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0x01); // version
    b.push(opcode);
    b.push(6); // resultType — carried raw, uninterpreted
    b.push(operands.len() as u8);
    for o in operands {
        b.extend_from_slice(o);
    }
    b.extend_from_slice(&result_handle);
    b.extend_from_slice(&7u32.to_be_bytes()); // hcuCost
    b.extend_from_slice(&(aux.len() as u16).to_be_bytes());
    b.extend_from_slice(aux);
    b
}

/// `trivialEncrypt`'s aux: value(8) then WIDTH(1).
///
/// The width is the raw bit width the backend takes — 64, not §3's log-coded
/// `resultType` of 6. Two encodings of one quantity live a byte apart in this
/// envelope, and the first version of this fixture used the code where the
/// width belongs. That is the same conflation the freeze review caught between
/// the specification, a unit test and the shipped precompile, which disagreed
/// three ways; it survives because nothing rejects a plausible number.
fn trivial(value: u64, width_bits: u8) -> Vec<u8> {
    let mut aux = value.to_be_bytes().to_vec();
    aux.push(width_bits);
    aux
}

fn handle(tag: u8) -> [u8; 32] {
    [tag; 32]
}

struct Fixture(Vec<RawEvent>);

impl StreamSource for Fixture {
    type Error = String;
    fn events(&self, _from: u64, _to: u64) -> Result<Vec<RawEvent>, String> {
        Ok(self.0.clone())
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32].into()).expect("fixed test key")
}

/// The backend's server key is thread-local state in the library, so every test
/// thread needs its own.
///
/// Worth stating rather than copying: this is a property of the FHE library's
/// global state, not of the service. A service running per-thread executors
/// would have to do the same thing, and discovering that from a panic inside a
/// dependency — which is how this test discovered it — is the expensive route.
fn arm_backend() {
    let (_ck, sk) = celar_zama::dev_keys();
    tfhe::set_server_key(sk);
}

#[test]
fn executes_in_canonical_order_and_attests_to_each() {
    arm_backend();
    // Delivered out of order on purpose: the add depends on the two encrypts,
    // so a consumer that executed as delivered would fail on a missing operand.
    let a = handle(0xAA);
    let b = handle(0xBB);
    let sum = handle(0xCC);

    let events = vec![
        RawEvent {
            at: StreamRef { height: 10, tx_index: 0, log_index: 2 },
            data: envelope(op::ADD, &[a, b], sum, &[]),
        },
        RawEvent {
            at: StreamRef { height: 10, tx_index: 0, log_index: 0 },
            data: envelope(op::TRIVIAL_ENCRYPT, &[], a, &trivial(11, 64)),
        },
        RawEvent {
            at: StreamRef { height: 10, tx_index: 0, log_index: 1 },
            data: envelope(op::TRIVIAL_ENCRYPT, &[], b, &trivial(31, 64)),
        },
    ];

    let mut svc = Service::new(Fixture(events), CHAIN_ID, key());
    let out = svc.poll(10, 10).expect("the range executes");

    assert_eq!(out.attestations.len(), 3, "one attestation per executed op");
    assert!(out.deferred.is_empty());

    let positions: Vec<u32> = out.attestations.iter().map(|x| x.at.log_index).collect();
    assert_eq!(positions, vec![0, 1, 2], "attested in canonical order, not delivery order");

    // The third attests to the add, whose result handle is the chain's.
    assert_eq!(out.attestations[2].result_handle, sum);
}

#[test]
fn the_signature_recovers_to_the_coprocessor_that_signed_it() {
    arm_backend();
    // This is the seam the chain checks: it recovers a signer from the preimage
    // and compares it against the claimed identity. If these two disagree, every
    // honest attestation is rejected on chain and nothing here would show it.
    let h = handle(0x01);
    let events = vec![RawEvent {
        at: StreamRef { height: 4, tx_index: 1, log_index: 0 },
        data: envelope(op::TRIVIAL_ENCRYPT, &[], h, &trivial(5, 64)),
    }];

    let mut svc = Service::new(Fixture(events), CHAIN_ID, key());
    let out = svc.poll(4, 4).expect("executes");
    let att = &out.attestations[0];

    assert_eq!(att.coprocessor_id, coprocessor_id(&key()));
    assert_eq!(att.signature.len(), 65);

    let preimage = signing_preimage(CHAIN_ID, &att.at, &att.result_handle, &att.ct_digest);
    let sig = Signature::from_slice(&att.signature[..64]).expect("64-byte r||s");
    let recid = RecoveryId::from_byte(att.signature[64]).expect("v in {0,1}");
    let recovered = VerifyingKey::recover_from_prehash(&preimage, &sig, recid).expect("recoverable");

    let mut k = Keccak256::new();
    k.update(&recovered.to_encoded_point(false).as_bytes()[1..]);
    let digest = k.finalize();
    assert_eq!(&digest[12..], att.coprocessor_id, "recovered signer must be the claimed id");
}

#[test]
fn admission_is_deferred_rather_than_attested_or_dropped() {
    // The body does not ride the stream, so this consumer cannot execute it —
    // and reporting it is the point: "nothing to attest here" and "nothing
    // happened here" are different statements.
    let mut aux = vec![0xEE; 32]; // commitment
    aux.extend_from_slice(&[0u8; 32]); // all-zero availability pointer
    let events = vec![RawEvent {
        at: StreamRef { height: 3, tx_index: 0, log_index: 0 },
        data: envelope(op::VERIFY_INPUT, &[], handle(0x09), &aux),
    }];

    let mut svc = Service::new(Fixture(events), CHAIN_ID, key());
    let out = svc.poll(3, 3).expect("a well-formed admission is not an error");

    assert!(out.attestations.is_empty(), "nothing executed, so nothing attested");
    // Asserting the REASON, not just the position. This test predates the
    // reason existing, and "deferred at height 3" was true of an aborted op's
    // dependent too - so the old assertion passed for two different causes and
    // could not tell them apart. The comment above it always claimed the
    // distinction; now the assertion carries it.
    assert_eq!(
        out.deferred,
        vec![Deferred {
            at: StreamRef { height: 3, tx_index: 0, log_index: 0 },
            reason: DeferReason::CiphertextBodyUnavailable,
        }]
    );
}

#[test]
fn a_malformed_event_halts_the_range_and_names_its_position() {
    arm_backend();
    // Skipping would execute later ops against operands that were never
    // produced — which either errors somewhere unrelated or succeeds against a
    // stale handle and attests to a computation the chain never described.
    let good = RawEvent {
        at: StreamRef { height: 1, tx_index: 0, log_index: 0 },
        data: envelope(op::TRIVIAL_ENCRYPT, &[], handle(0x01), &trivial(1, 64)),
    };
    let bad = RawEvent {
        at: StreamRef { height: 1, tx_index: 0, log_index: 1 },
        data: vec![0x02, 0x02, 0x06, 0x00], // version 0x02: not ours
    };

    let mut svc = Service::new(Fixture(vec![good, bad]), CHAIN_ID, key());
    match svc.poll(1, 1) {
        Err(ServiceError::Decode { at, .. }) => {
            assert_eq!(at, StreamRef { height: 1, tx_index: 0, log_index: 1 })
        }
        other => panic!("an unknown envelope version must halt the range, got {other:?}"),
    }
}

#[test]
fn an_unresolvable_operand_halts_rather_than_attesting() {
    // An add whose operands were never produced. The danger is not the error —
    // it is a consumer that treats this as a gap and carries on.
    let events = vec![RawEvent {
        at: StreamRef { height: 2, tx_index: 0, log_index: 0 },
        data: envelope(op::ADD, &[handle(0xF1), handle(0xF2)], handle(0xF3), &[]),
    }];

    let mut svc = Service::new(Fixture(events), CHAIN_ID, key());
    match svc.poll(2, 2) {
        Err(ServiceError::Exec { at, .. }) => {
            assert_eq!(at, StreamRef { height: 2, tx_index: 0, log_index: 0 })
        }
        other => panic!("an unknown operand must halt, got {other:?}"),
    }
}
