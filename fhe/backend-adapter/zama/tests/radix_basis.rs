//! Does the digest basis bind HOW a value was computed, or only what it is?
//!
//! If the serialised radix carries per-block bookkeeping (degree, noise
//! level, moduli), then two coprocessors on different library versions
//! could digest identical computation differently — which would make
//! identical tfhe-rs versions consensus-critical rather than recommended.

use celar_zama::backend::Backend;
use celar_zama::dev_keys;
use tfhe::set_server_key;

fn setup() -> (Backend, tfhe::ClientKey) {
    let (ck, sk) = dev_keys();
    set_server_key(sk);
    (Backend::new(), ck)
}

fn diff(a: &[u8], b: &[u8]) -> Vec<usize> {
    a.iter().zip(b).enumerate()
        .filter(|(_, (x, y))| x != y).map(|(i, _)| i).collect()
}

/// The comparison as originally proposed. Recorded, but it does NOT
/// discriminate: these are different ciphertexts, so their bytes differ
/// whether or not bookkeeping is serialised.
#[test]
fn same_value_different_provenance() {
    let (mut be, ck) = setup();
    let direct = be.trivial_encrypt(5, 64).unwrap();
    let twelve = be.trivial_encrypt(12, 64).unwrap();
    let seven  = be.trivial_encrypt(7, 64).unwrap();
    let derived = be.sub(twelve, seven).unwrap();

    assert_eq!(be.oracle_uint(direct, &ck).unwrap(), 5);
    assert_eq!(be.oracle_uint(derived, &ck).unwrap(), 5);

    let a = be.digest_basis(direct).unwrap();
    let b = be.digest_basis(derived).unwrap();
    println!("direct  len={} derived len={}", a.len(), b.len());
    println!("equal={}  differing_bytes={}", a == b,
             if a.len() == b.len() { diff(&a, &b).len() } else { usize::MAX });
}

/// THE DISCRIMINATOR. Adding a trivially-encrypted zero leaves the value
/// and the body arithmetic alone, but the operation updates per-block
/// bookkeeping. If the bytes move, the bookkeeping is in the digest.
#[test]
fn adding_a_trivial_zero_should_not_move_the_basis() {
    let (mut be, ck) = setup();
    let x = be.trivial_encrypt(5, 64).unwrap();
    let z = be.trivial_encrypt(0, 64).unwrap();
    let y = be.add(x, z).unwrap();

    assert_eq!(be.oracle_uint(x, &ck).unwrap(), 5);
    assert_eq!(be.oracle_uint(y, &ck).unwrap(), 5);

    let a = be.digest_basis(x).unwrap();
    let b = be.digest_basis(y).unwrap();

    println!("x len={}  x+0 len={}", a.len(), b.len());
    if a.len() == b.len() {
        let d = diff(&a, &b);
        println!("same length; {} differing byte offsets: {:?}",
                 d.len(), &d[..d.len().min(24)]);
    } else {
        println!("LENGTHS DIFFER — structural, not just field values");
    }
    println!("identical={}", a == b);
}
