//! The abort event (§3.4).
//!
//! Three properties, and the third is the one worth having: an abort must not
//! register its `resultHandle`. That field carries the ABORTED op's handle, so
//! a consumer treating it like every other event's result would register a
//! handle for an op that never ran — and then execute later ops against it,
//! attesting to a computation the chain never described. It is the one misread
//! in this envelope that fails silently.

use celar_coprocessor::exec::{op, Executor, Outcome};
use celar_coprocessor::ingest::{RawEvent, StreamRef, StreamSource};
use celar_coprocessor::opstream::{decode, ENVELOPE_VERSION};
use celar_coprocessor::service::Service;
use k256::ecdsa::SigningKey;
use tfhe::set_server_key;

fn arm() {
    let (_ck, sk) = celar_zama::dev_keys();
    set_server_key(sk);
}

/// §3's envelope, written out here rather than reused from the decoder so a
/// layout change breaks this test instead of being absorbed by it.
fn envelope(opcode: u8, result_type: u8, operands: &[[u8; 32]], result_handle: [u8; 32], hcu: u32, aux: &[u8]) -> Vec<u8> {
    let mut d = vec![ENVELOPE_VERSION, opcode, result_type, operands.len() as u8];
    for o in operands {
        d.extend_from_slice(o);
    }
    d.extend_from_slice(&result_handle);
    d.extend_from_slice(&hcu.to_be_bytes());
    d.extend_from_slice(&(aux.len() as u16).to_be_bytes());
    d.extend_from_slice(aux);
    d
}

fn at(height: u64, log: u32) -> StreamRef {
    StreamRef { height, tx_index: 0, log_index: log }
}

fn stream_ref_bytes(r: &StreamRef) -> Vec<u8> {
    let mut b = r.height.to_be_bytes().to_vec();
    b.extend_from_slice(&r.tx_index.to_be_bytes());
    b.extend_from_slice(&r.log_index.to_be_bytes());
    b
}

/// trivialEncrypt(value, 64) — one event, no operands, no dependencies.
fn trivial(value: u64, handle: u8) -> Vec<u8> {
    let mut aux = value.to_be_bytes().to_vec();
    aux.push(0x40);
    envelope(op::TRIVIAL_ENCRYPT, 6, &[], [handle; 32], 10_000, &aux)
}

fn abort_of(victim: &StreamRef, victim_handle: [u8; 32]) -> Vec<u8> {
    envelope(op::ABORT, 0xFF, &[], victim_handle, 0, &stream_ref_bytes(victim))
}

struct Fixed(Vec<RawEvent>);

impl StreamSource for Fixed {
    type Error = ();
    fn events(&self, _from: u64, _to: u64) -> Result<Vec<RawEvent>, ()> {
        Ok(self.0.clone())
    }
}

#[test]
fn an_abort_names_the_op_that_died_rather_than_itself() {
    arm();
    let victim = at(9, 2);
    let ev = decode(&abort_of(&victim, [0xAB; 32])).expect("abort decodes");
    match Executor::new().execute(&ev).expect("abort is not an error") {
        Outcome::Aborted { aborted_at, aborted_handle } => {
            assert_eq!(aborted_at, victim, "aux must carry the aborted position");
            assert_eq!(aborted_handle, [0xAB; 32], "resultHandle is the aborted op's");
        }
        other => panic!("expected an abort outcome, got {other:?}"),
    }
}

#[test]
fn an_abort_whose_aux_is_not_a_position_is_refused() {
    arm();
    let ev = decode(&envelope(op::ABORT, 0xFF, &[], [1; 32], 0, &[0u8; 8]))
        .expect("envelope still decodes");
    assert!(
        Executor::new().execute(&ev).is_err(),
        "a short aux was accepted: the aborted position would be read from \
         whatever happened to be there"
    );
}

#[test]
fn consumption_halts_at_an_abort_and_the_dead_handle_is_never_registered() {
    arm();
    let before = at(1, 0);
    let abort_at = at(1, 1);
    let after = at(1, 2);
    let dead = [0xDD; 32];

    let source = Fixed(vec![
        RawEvent { at: before, data: trivial(7, 0x01) },
        RawEvent { at: abort_at, data: abort_of(&at(1, 9), dead) },
        RawEvent { at: after, data: trivial(9, 0x02) },
    ]);

    let key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let mut svc = Service::new(source, 1, key);
    let polled = svc.poll(1, 1).expect("a well-formed abort is not an error");

    assert_eq!(polled.attestations.len(), 1, "only the op before the abort is attested");
    assert_eq!(polled.attestations[0].at, before);
    assert_eq!(polled.aborts.len(), 1);
    assert_eq!(polled.aborts[0].aborted_at, at(1, 9));
    assert_eq!(polled.halted_at, Some(abort_at));

    // The property this file exists for.
    assert!(
        svc.executor().resolve(&dead).is_none(),
        "the aborted op's handle was registered: later ops would execute \
         against a result the chain says does not exist"
    );
}
