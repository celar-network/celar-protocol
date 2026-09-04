//! §8(ii), made enforceable.
//!
//! *"A coprocessor MUST NOT optimise the op-stream — including optimisations
//! that preserve the value… Execute the stream exactly as emitted, op for op,
//! whatever a compiler would consider obviously safe."*
//!
//! A prohibition with no failing test is a comment. This asserts the property
//! the prohibition rests on: **adding a trivially encrypted zero changes the
//! digest without changing the value**, so a coprocessor that folded it away
//! would produce a correct result and a different attestation — which §8's
//! fraud game cannot distinguish from a cheat.
//!
//! If this test ever fails, §8(ii) is not merely unenforced: its premise is
//! false, and that is a finding for the specification rather than a bug here.

use celar_coprocessor::exec::{op, Executor, Outcome};
use celar_coprocessor::opstream::StreamEvent;
use tfhe::set_server_key;

fn handle(b: u8) -> [u8; 32] {
    [b; 32]
}

fn ev(opcode: u8, operands: Vec<[u8; 32]>, result: [u8; 32], aux: Vec<u8>) -> StreamEvent {
    StreamEvent {
        version: 0x01,
        opcode,
        result_type: 6, // euint64
        operands,
        result_handle: result,
        hcu_cost: 0,
        aux,
    }
}

fn trivial(value: u64, result: [u8; 32]) -> StreamEvent {
    let mut aux = value.to_be_bytes().to_vec();
    aux.push(64); // width
    ev(op::TRIVIAL_ENCRYPT, vec![], result, aux)
}

fn executed(o: Outcome) -> u64 {
    match o {
        Outcome::Executed(h) => h,
        other => panic!("expected execution, got {other:?}"),
    }
}

#[test]
fn folding_a_trivial_zero_changes_the_digest_but_not_the_value() {
    let (ck, sk) = celar_zama::dev_keys();
    set_server_key(sk);

    // The stream as emitted: 7, then 0, then their sum.
    let mut honest = Executor::new();
    executed(honest.execute(&trivial(7, handle(1))).unwrap());
    executed(honest.execute(&trivial(0, handle(2))).unwrap());
    let sum = executed(
        honest
            .execute(&ev(op::ADD, vec![handle(1), handle(2)], handle(3), vec![]))
            .unwrap(),
    );

    // What a "safe" optimiser would do instead: notice the addend is zero and
    // hand back the original operand.
    let mut folded = Executor::new();
    let seven = executed(folded.execute(&trivial(7, handle(1))).unwrap());

    let d_honest = honest.backend().digest_basis(sum).unwrap();
    let d_folded = folded.backend().digest_basis(seven).unwrap();

    assert_eq!(
        honest.backend().oracle_uint(sum, &ck).unwrap(),
        folded.backend().oracle_uint(seven, &ck).unwrap(),
        "precondition: the fold must preserve the value, or this proves nothing"
    );
    assert_ne!(
        d_honest, d_folded,
        "adding a trivial zero left the digest unchanged - if this holds, \
         section 8(ii)'s premise is false and the specification needs to know"
    );
}

/// The operands a stream names must be the ones executed, in signature order.
/// `sub` is not commutative, so a consumer that reordered would produce a
/// clean, wrong, attestable result.
#[test]
fn operand_order_is_respected() {
    let (ck, sk) = celar_zama::dev_keys();
    set_server_key(sk);
    let mut x = Executor::new();
    executed(x.execute(&trivial(10, handle(1))).unwrap());
    executed(x.execute(&trivial(4, handle(2))).unwrap());
    let d = executed(
        x.execute(&ev(op::SUB, vec![handle(1), handle(2)], handle(3), vec![]))
            .unwrap(),
    );
    assert_eq!(x.backend().oracle_uint(d, &ck).unwrap(), 6);
}

/// Joining mid-stream names handles we never executed. Refusing is the only
/// safe answer: attesting to a result computed from a guessed operand is worse
/// than not attesting at all.
#[test]
fn an_unknown_operand_is_refused() {
    let mut x = Executor::new();
    let r = x.execute(&ev(op::ADD, vec![handle(9), handle(9)], handle(3), vec![]));
    assert!(r.is_err(), "an operand we never executed must not resolve");
}
