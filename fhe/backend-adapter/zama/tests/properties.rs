//! Property tests over the euint64 range.
//! 
//! The corpus tests in `ops.rs` check five fixed points. These check
//! *invariants* over values drawn across the whole ragne, which is where edge
//! cases nobody thought to wirte down are found.
//! 
//! Operands are REAL encryptions. Trivial encryption produces noiseless 
//! ciphertext that the library short-circuits, so it exercises neither 
//! the noise budget nor the real code path - a mistake that once voided an entire 
//! round of measurements
//! 
//! Ignored by default: each encrypted operation costs hundreds of milliseconds
//! Run explicitly:
//! 
//! cargo test --release --test properties -- --ignored --nocapture

use celar_zama::backend::Backend;
use celar_zama::dev_keys;
use tfhe::set_server_key;

///Cases are property. Raise when investigating a failure, not routinely.
const CASES: usize = 8;

/// Fixed seed: every run is identical, so a counterexample is reproducible.
/// Printed with any failure.
const SEED: u64 = 0xCE1A_2026_0808_0001;

/// xorshift64*, inline to avoid a dependency and keep the sequence stable
/// across toolchains.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }
    fn next (&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Boundaries where wrapping, comparison and truncation behave differently -
/// always covered, never left to the draw.
const EDGES: [u64; 5] = [0, 1, u64::MAX, u64::MAX - 1, 1 << 63];

fn setup() -> (Backend, tfhe::ClientKey) {
   let (ck, sk) = dev_keys();
   set_server_key(sk);
   (Backend::new(), ck) 
}

fn cases() -> Vec<(u64, u64)> {
    let mut rng = Rng::new(SEED);
    let mut v: Vec<(u64, u64)> = (0..CASES).map(|_| (rng.next(), rng.next())).collect();
    for (i, &e) in EDGES.iter().enumerate() {
        v.push((e, EDGES[(i + 1) % EDGES.len()]));
    }
    v
}

#[test]
#[ignore]
fn arithmetic_agrees_with_wrapping_plaintext() {
    let ( mut be, ck) = setup();
    for (x,y) in cases() {
        let a = be.encrypt(x,64, &ck).unwrap();
        let b = be.encrypt(y,64, &ck).unwrap();

        let h = be.add(a, b).unwrap();
        assert_eq!(
            be.oracle_uint(h, &ck).unwrap(),
            x.wrapping_add(y),
            "add failed: seed={SEED:#x} x={x} y={y}"
        );

        let h = be.sub(a,b).unwrap();
        assert_eq!(
            be.oracle_uint(h, &ck).unwrap(),
            x.wrapping_sub(y),
            "sub failed: seed={SEED:#x} x={x} y={y}"
        ); 
    }
}

#[test]
#[ignore]
fn comparisons_are_consistent_and_trichotomous() {
    let ( mut be, ck) = setup();
    for (x,y) in cases() {
        let a = be.encrypt(x,64, &ck).unwrap();
        let b = be.encrypt(y,64, &ck).unwrap();

        let h = be.lt(a, b).unwrap();
        let lt = be.oracle_bool(h, &ck).unwrap();
        let h = be.eq(a, b).unwrap();
        let eq = be.oracle_bool(h, &ck).unwrap();
        let h = be.le(a, b).unwrap();
        let le = be.oracle_bool(h, &ck).unwrap();

        let ctx = format!("seed={SEED:#x} x={x} y={y}");
        assert_eq!(lt, x < y, "lt disagrees with plaintext: {ctx}");
        assert_eq!(eq, x == y, "eq disagrees with plaintext: {ctx}");
        assert_eq!(le, x <= y, "le disagrees with plaintext: {ctx}");

        //internal consistency: an oracle can agree while the relations
        //contradict one another
        assert_eq!(le, lt || eq, "le != (lt or eq): {ctx}");
        assert!(!(lt && eq), "lt and eq both true: {ctx}");
    }
}

#[test]
#[ignore]
fn select_is_total() {
    // The branchless primitive must return one of its two branches. if it
    // could ever produces a third value, encrypted control flow is unsound.
    let (mut be, ck) = setup();
    for(x,y) in cases() {
        let a = be.encrypt(x,64, &ck).unwrap();
        let b = be.encrypt(y,64, &ck).unwrap();

        let cond = be.le(a,b).unwrap();
        let h = be.select(cond, a, b).unwrap();
        let got = be.oracle_uint(h, &ck).unwrap();

        let ctx = format!("seed={SEED:#x} x={x} y={y}");
        assert!(got == x || got == y , "select produced a thrid value: {ctx}");
        assert_eq!(got, if x <= y { x } else { y }, "select chose wrong: {ctx}");
    }
}

#[test]
#[ignore]
fn cast_truncates_exactly() {
    let (mut be, ck) = setup();
    for (x, _) in cases() {
        let a = be.encrypt(x, 64, &ck).unwrap();
        for k in [8u8, 16, 32, 64] {
            let mask = if k >= 64 { u64::MAX } else { (1u64 << k) - 1 };
            let h = be.cast(a, k).unwrap();
            assert_eq!(
                be.oracle_uint(h, &ck).unwrap(),
                x & mask,
                "cast to {k} bits failed: seed={SEED:#x} x={x}"
            );
        }
    }
}

#[test]
#[ignore]
fn boolean_algebra_holds() {
    let (mut be, ck) = setup();
    for (x, y) in cases() {
        let a = be.encrypt(x, 64, &ck).unwrap();
        let b = be.encrypt(y, 64, &ck).unwrap();

        // two encrypted predicates, derived rather than encrypted directly
        let p = be.le(a, b).unwrap();
        let q = be.le(b, a).unwrap();
        let ctx = format!("seed={SEED:#x} x={x} y={y}");

        // De Morgan: !(p && q) == !p || !q
        let and_pq = be.and(p, q).unwrap();
        let lhs = be.not(and_pq).unwrap();
        let not_p = be.not(p).unwrap();
        let not_q = be.not(q).unwrap();
        let rhs = be.or(not_p, not_q).unwrap();
        assert_eq!(
            be.oracle_bool(lhs, &ck).unwrap(),
            be.oracle_bool(rhs, &ck).unwrap(),
            "De Morgan violated: {ctx}"
        );

        // double negation
        let nn = be.not(not_p).unwrap();
        assert_eq!(
            be.oracle_bool(nn, &ck).unwrap(),
            be.oracle_bool(p, &ck).unwrap(),
            "double negation violated: {ctx}"
        );
    }
}