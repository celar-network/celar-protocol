//! Determinism: the same stream, executed twice, must digest identically.
//!
//! This is the property the fraud game rests on. Sampled re-execution can only
//! separate dishonesty from honest variation if there IS no honest variation,
//! so a coprocessor that produced different bytes for the same work would make
//! every attestation unfalsifiable.
//!
//! Scope, stated so this is not read as more than it is: two executors in ONE
//! process on ONE machine. Cross-hardware reproducibility is the open question
//! the backend notes record, and nothing here touches it.

use celar_coprocessor::exec::{op, Executor, Outcome};
use celar_coprocessor::opstream::StreamEvent;
use tfhe::set_server_key;

fn h(b: u8) -> [u8; 32] { [b; 32] }

fn ev(opcode: u8, operands: Vec<[u8; 32]>, result: [u8; 32], aux: Vec<u8>) -> StreamEvent {
    StreamEvent { version: 1, opcode, result_type: 6, operands, result_handle: result,
                  hcu_cost: 0, aux }
}

fn trivial(v: u64, result: [u8; 32]) -> StreamEvent {
    let mut aux = v.to_be_bytes().to_vec();
    aux.push(64);
    ev(op::TRIVIAL_ENCRYPT, vec![], result, aux)
}

fn got(o: Outcome) -> u64 {
    match o { Outcome::Executed(x) => x, other => panic!("expected execution, got {other:?}") }
}

/// A small stream with a comparison and a select in it, so the run exercises
/// more than addition.
///
/// The select's TRUE branch must be the seed-dependent operand. With the
/// operands the other way round both runs selected the same constant, so two
/// genuinely different streams produced the same result by the same path -
/// identical digests were correct and the control was measuring nothing.
fn run(seed: u64) -> Vec<u8> {
    let mut x = Executor::new();
    got(x.execute(&trivial(seed, h(1))).unwrap());
    got(x.execute(&trivial(5, h(2))).unwrap());
    got(x.execute(&ev(op::ADD, vec![h(1), h(2)], h(3), vec![])).unwrap());
    got(x.execute(&ev(op::LE, vec![h(2), h(3)], h(4), vec![])).unwrap());
    let picked = got(x.execute(&ev(op::SELECT, vec![h(4), h(1), h(2)], h(5), vec![])).unwrap());
    x.backend().digest_basis(picked).unwrap()
}

#[test]
fn the_same_stream_digests_identically() {
    let (_ck, sk) = celar_zama::dev_keys();
    set_server_key(sk);
    assert_eq!(run(7), run(7), "identical work produced different bytes");
}

/// The control. Without it, a digest function that returned a constant would
/// satisfy the test above - the same defect class as a config assertion tested
/// against its own default.
#[test]
fn different_streams_do_not_digest_identically() {
    let (_ck, sk) = celar_zama::dev_keys();
    set_server_key(sk);
    assert_ne!(run(7), run(9), "different work produced identical bytes");
}
