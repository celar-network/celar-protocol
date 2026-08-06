//! Correctness of the ABI compute operations against a plaintext oracle.
//! One key paris shared across the suite: key generation dominates runtime
//! and the operations under test do not depend on which key is used.

use celar_zama::backend::Backend;
use celar_zama::dev_keys;
use tfhe::set_server_key;

const MASK64: u64 = u64::MAX;

/// Coprus from the abke-off spec: zero, max, the overflow, boundary, a mid
/// value, and an arbitrary one.
const CORPUS: [(&str, u64, u64); 5] = [
    ("zero", 0 , 1),
    ("max", MASK64, 500),
    ("boundary", MASK64 -1, 2),
    ("mid", 1_000_000_000, 999),
    ("random", 0xDEAD_BEEF_CAFE, 42),
];

fn backend() -> (Backend,tfhe::ClientKey) {
    let (ck, sk) = dev_keys();
    set_server_key(sk);
    (Backend::new(), ck)
}

#[test]
fn arithmetic_and_comparison_match_plaintext() {
    let (mut be, ck) = backend();

    for (name, a_pt, b_pt ) in CORPUS {
        let a = be.trivial_encrypt(a_pt, 64).unwrap();
        let b = be.trivial_encrypt(b_pt, 64).unwrap();
        let sum = be.add(a,b).unwrap();
        assert_eq!(
            be.oracle_uint(sum, &ck).unwrap(),
            a_pt.wrapping_add(b_pt),
            "add {name}"
        );

        let diff = be.sub(a,b).unwrap();
        assert_eq!(
            be.oracle_uint(diff, &ck).unwrap(),
            a_pt.wrapping_sub(b_pt),
            "sub {name}"
        );

        let le = be.le(a,b).unwrap();
        assert_eq!(be.oracle_bool(le, &ck).unwrap(), a_pt <= b_pt, "le {name}");

        let lt = be.lt(a,b).unwrap();
        assert_eq!(be.oracle_bool(lt, &ck).unwrap(), a_pt < b_pt, "lt {name}");

        let eq = be.eq(a, b).unwrap();
        assert_eq!(be.oracle_bool(eq, &ck).unwrap(), a_pt == b_pt, "eq {name}");
    }
}

#[test]
fn boolean_combinators_match_plaintext() {
    let (mut be, ck) = backend();
    let zero = be.trivial_encrypt(0,64 ).unwrap();
    let one = be.trivial_encrypt(1, 64).unwrap();

    for (x,y) in [(false, false), (false, true), (true, false), (true, true)] {
        // derive ebools through a comparison rather than by encrypting them
        let bx = if x { be.eq(one, one) } else { be.eq(one, zero) }.unwrap();
        let by = if y { be.eq(one, one) } else { be.eq(one, zero) }.unwrap();

        let and = be.and(bx, by).unwrap();
        assert_eq!(be.oracle_bool(and, &ck).unwrap(), x && y, "and {x} {y}");

        let or = be.or(bx, by).unwrap();
        assert_eq!(be.oracle_bool(or, &ck).unwrap(), x || y, "or {x} {y}");

        let not = be.not(bx).unwrap();
        assert_eq!(be.oracle_bool(not, &ck).unwrap(), !x, "not {x} {y}");
    }
}

#[test]
fn select_is_branchless_and_correct() {
    let (mut be, ck) = backend();
    let a = be.trivial_encrypt(111, 64).unwrap();
    let b = be.trivial_encrypt(222, 64).unwrap();

    let small = be.trivial_encrypt(1, 64).unwrap();
    let big = be.trivial_encrypt(9, 64).unwrap();

    let cond_true = be.le(small,big).unwrap(); // 9 >= 1
    let picked = be.select(cond_true, a,b).unwrap();
    assert_eq!(be.oracle_uint(picked, &ck).unwrap(), 111);

    let cond_false = be.le(big,small).unwrap(); // 9 <= 1
    let picked = be.select(cond_false, a, b).unwrap();
    assert_eq!(be.oracle_uint(picked, &ck).unwrap(), 222);
}

#[test]
fn cast_truncates_to_target_width() {
    let (mut be, ck) = backend();
    let v = be.trivial_encrypt(300, 64).unwrap();

    let to8 = be.cast(v, 8).unwrap();
    assert_eq!(be.oracle_uint(to8, &ck).unwrap(), 300 & 0xFF);

    let to16 = be.cast(v, 16).unwrap();
    assert_eq!(be.oracle_uint(to16, &ck).unwrap(), 300);

    let to64 = be.cast(v, 64).unwrap();
    assert_eq!(be.oracle_uint(to64, &ck).unwrap(), 300);
}

#[test]
fn confidential_transfer_pattern() {
    // The branchless transfer: move the amount only if the sender can afford
    // it and the recipient will not overflow. No branch observes the outcome.
    let (mut be, ck) = backend();

    let run = |be: &mut Backend, amount: u64, bal_s: u64, bal_r: u64| {
        let amt = be.trivial_encrypt(amount, 64).unwrap();
        let s = be.trivial_encrypt(bal_s, 64).unwrap();
        let r = be.trivial_encrypt(bal_r, 64).unwrap();
        let zero = be.trivial_encrypt(0, 64).unwrap();
        let maxv = be.trivial_encrypt(u64::MAX, 64).unwrap();

        let affordable = be.le(amt, s).unwrap();
        let headroom = be.sub(maxv, r).unwrap();
        let fits = be.le(amt, headroom).unwrap();
        let ok = be.and(affordable, fits).unwrap();

        let moved = be.select(ok, amt, zero).unwrap();
        let new_s = be.sub(s, moved).unwrap();
        let new_r = be.add(r, moved).unwrap();
        (
            be.oracle_uint(new_s, &ck).unwrap(),
            be.oracle_uint(new_r, &ck).unwrap(),
        )
    };

    // sufficient funds: the amount moves
    assert_eq!(run(&mut be, 100, 500, 50), (400, 150));
    // insufficient funds: nothing moves, and no error is observable
    assert_eq!(run(&mut be, 900, 500, 50), (500, 50));
    // exact balance: boundary case must still move
    assert_eq!(run(&mut be, 500, 500, 50), (0, 550));
}

#[test]
fn type_confusion_is_rejected() {
    let (mut be, _ck) = backend();
    let u = be.trivial_encrypt(5, 64).unwrap();
    let b = be.le(u, u).unwrap();

    assert!(be.and(u, u).is_err(), "integers must not be usable as booleans");
    assert!(be.add(b, b).is_err(), "booleans must not be usable as integers");
    assert!(be.add(u, 9999).is_err(), "unknown handles must be rejected");
    assert!(be.trivial_encrypt(1, 7).is_err(), "invalid width must be rejected");
}