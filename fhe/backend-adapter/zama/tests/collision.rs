//! Two honest accounts minted the same amount share a balance handle.
//! Is that one underlying balance, or two?
//!
//! The chain-layer test cannot answer this: `_balances` is keyed per
//! account, so `sub(H100, 40)` yields `H60` whether or not anyone else
//! did the same, and nothing reverts in either world. The question is
//! about VALUES, so it has to be asked where values exist.

use celar_zama::backend::Backend;
use celar_zama::dev_keys;
use tfhe::set_server_key;

fn setup() -> (Backend, tfhe::ClientKey) {
    let (ck, sk) = dev_keys();
    set_server_key(sk);
    (Backend::new(), ck)
}

/// The premise, reproduced at the backend: the collision is not an
/// artifact of the chain's handle derivation. `trivial_encrypt` is
/// deterministic by construction — it carries no randomness — so the
/// same mint by two accounts yields the same ciphertext.
#[test]
fn two_honest_mints_of_the_same_amount_collide() {
    let (mut be, ck) = setup();

    let zero_a = be.trivial_encrypt(0, 64).unwrap();
    let zero_b = be.trivial_encrypt(0, 64).unwrap();
    assert_eq!(
        be.digest_basis(zero_a).unwrap(),
        be.digest_basis(zero_b).unwrap(),
        "the encrypted zero must be shared — this is what _ensure hands \
         every account"
    );

    let minted_a = be.trivial_encrypt(100, 64).unwrap();
    let minted_b = be.trivial_encrypt(100, 64).unwrap();
    let bal_a = be.add(zero_a, minted_a).unwrap();
    let bal_b = be.add(zero_b, minted_b).unwrap();

    assert_eq!(
        be.digest_basis(bal_a).unwrap(),
        be.digest_basis(bal_b).unwrap(),
        "two accounts minted the same amount must collide; if they do not, \
         the premise of this test has changed and it is moot"
    );
    assert_eq!(be.oracle_uint(bal_a, &ck).unwrap(), 100);
}

/// THE VERDICT. Both holders spend from the shared handle; then the
/// original is decrypted again.
#[test]
fn a_shared_handle_is_two_balances_not_one() {
    let (mut be, ck) = setup();

    let zero = be.trivial_encrypt(0, 64).unwrap();
    let hundred = be.trivial_encrypt(100, 64).unwrap();
    let bal_a = be.add(zero, hundred).unwrap();
    let bal_b = be.add(zero, hundred).unwrap();
    assert_eq!(
        be.digest_basis(bal_a).unwrap(),
        be.digest_basis(bal_b).unwrap(),
    );

    // The contract's actual path is branchless:
    //   actual = select(le(amount, fromBal), amount, 0)
    let amount = be.trivial_encrypt(40, 64).unwrap();
    let fits_a = be.le(amount, bal_a).unwrap();
    let actual_a = be.select(fits_a, amount, zero).unwrap();
    let fits_b = be.le(amount, bal_b).unwrap();
    let actual_b = be.select(fits_b, amount, zero).unwrap();

    // If select is inverted, say so here rather than in the verdict.
    assert_eq!(be.oracle_uint(actual_a, &ck).unwrap(), 40,
        "select did not yield the amount; the branchless path is wrong");

    let new_a = be.sub(bal_a, actual_a).unwrap();
    let recv_c = be.add(zero, actual_a).unwrap();
    let new_b = be.sub(bal_b, actual_b).unwrap();
    let recv_d = be.add(zero, actual_b).unwrap();

    // --- the decisive check -------------------------------------
    assert_eq!(
        be.oracle_uint(bal_a, &ck).unwrap(), 100,
        "the shared operand was MUTATED by the spends: two principals \
         drew down one object. This is a double-spend path and the \
         claimant set must not merge."
    );

    assert_eq!(be.oracle_uint(new_a, &ck).unwrap(), 60);
    assert_eq!(be.oracle_uint(new_b, &ck).unwrap(), 60);
    assert_eq!(be.oracle_uint(recv_c, &ck).unwrap(), 40);
    assert_eq!(be.oracle_uint(recv_d, &ck).unwrap(), 40);

    // Solvency closes: 60 + 60 + 40 + 40 == the 200 that was minted.
    let supply = be.add(bal_a, hundred).unwrap();
    assert_eq!(be.oracle_uint(supply, &ck).unwrap(), 200);

    // And the collision persists post-spend — it is a standing property
    // of equal-valued state, not an artifact of the mint path.
    assert_eq!(
        be.digest_basis(new_a).unwrap(),
        be.digest_basis(new_b).unwrap(),
        "post-spend states of equal value must still collide",
    );
}
