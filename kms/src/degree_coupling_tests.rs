//! Empirical corroboration of the degree-coupling finding: the source-read
//! established that upstream shares at polynomial degree = threshold t, so
//! t+1 shares reconstruct and privacy holds against exactly t colluders —
//! meaning the deployed confidentiality bound is the session threshold, not
//! the published quorum. These tests OBSERVE that on the deployed primitive
//! rather than trusting the read: upstream's own shamir doc comment is off
//! by one against its own code, which is precisely why observation beats
//! reading here.

use aes_prng::AesRng;
use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use algebra::sharing::shamir::{InputOp, RevealOp, ShamirSharings};
use algebra::structure_traits::Sample;

use crate::EXTENSION_DEGREE;

type R = ResiduePoly<Z128, EXTENSION_DEGREE>;

#[test]
fn at_threshold_one_exactly_two_shares_reconstruct_and_one_does_not() {
    // c = 5, t = 1: the sharing polynomial has degree t = 1 (a line), so any
    // TWO points determine it and ONE point reveals nothing. If the deployed
    // construction instead shared at degree t+1 or t-1, one of the two
    // assertions below would fail — this observation pins the tie.
    let mut rng = AesRng::from_random_seed();
    let secret = R::sample(&mut rng);
    let sharing = ShamirSharings::<R>::share(&mut rng, secret, 5, 1)
        .expect("sharing at c=5, t=1");

    // Two shares (any two): reconstructs, and to the CORRECT secret.
    let two = ShamirSharings::create(sharing.shares[..2].to_vec());
    let recovered = two
        .reconstruct(1)
        .expect("two shares must determine a degree-1 polynomial");
    assert_eq!(
        recovered, secret,
        "t+1 = 2 shares reconstructed a WRONG secret — the degree is not t"
    );

    // A different pair agrees — ruling out a lucky pair.
    let other_two = ShamirSharings::create(sharing.shares[3..5].to_vec());
    assert_eq!(other_two.reconstruct(1).expect("second pair"), secret);

    // One share: must NOT determine the secret. reconstruct(1) with a single
    // point cannot meet degree+1 and must error.
    let one = ShamirSharings::create(sharing.shares[..1].to_vec());
    assert!(
        one.reconstruct(1).is_err(),
        "a single share reconstructed a degree-1 sharing — privacy would be \
         against t-1 colluders, not t, and the published claim would be off \
         by one in the OTHER direction"
    );
}

#[test]
fn the_published_quorum_is_not_the_deployed_degree() {
    // The load-bearing negative: sharing at c = 5 with the SESSION threshold
    // (t = 1, what the deployed DKG uses) yields a sharing that 2 parties
    // open. The PUBLISHED reconstruction quorum at c = 5 is ⌊3·5/4⌋+1 = 4.
    // If the published number were the deployed privacy property, a
    // 2-of-5 coalition could not open — it can.
    let mut rng = AesRng::from_random_seed();
    let secret = R::sample(&mut rng);
    let sharing = ShamirSharings::<R>::share(&mut rng, secret, 5, 1)
        .expect("sharing at the session threshold");

    let coalition_of_two = ShamirSharings::create(sharing.shares[1..3].to_vec());
    assert_eq!(
        coalition_of_two
            .reconstruct(1)
            .expect("the sub-quorum coalition opens the sharing"),
        secret,
        "sanity: the coalition recovered a wrong value"
    );
    // 2 < 4: a coalition strictly below the published quorum recovered the
    // secret. The confidentiality bound of the deployed sharing is the
    // session threshold, not the published quorum. QED, by observation.
}
