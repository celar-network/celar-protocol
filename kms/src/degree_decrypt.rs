//! Degree-aware flooded reconstruction — the decrypt-side consumer of the
//! degree-decoupled flooding mask.
//!
//! When a key's sharing degree is decoupled from the committee's corruption
//! threshold, the flooding mask is born at the key's degree (see
//! [`crate::mask_supply`]). Reconstruction on the decrypt path must then also
//! happen at the key's degree, not the session threshold. This module is the
//! step that combines the two: each party's partial decryption `b - ⟨a, s_j⟩`
//! is a share of the phase over the degree-`d` key sharing; adding party `j`'s
//! share of the sealed mask gives a share of `phase + mask` at the same degree;
//! reconstructing that sharing yields the flooded phase, from which the
//! plaintext is decoded.
//!
//! **Reed–Solomon error tolerance.** Reconstructing a degree-`d` sharing from
//! `n` received shares tolerates `⌊(n − d − 1)/2⌋` faulty or missing shares —
//! the same geometry the two-sets reshare uses. The degree is the
//! confidentiality parameter; the tolerance is what the committee's corruption
//! model must stay within.
//!
//! **Seams this module does NOT cross:**
//! - The partials come from `partial_decrypt128` over the key shares (existing
//!   decrypt machinery); this module takes them as input.
//! - Decoding the flooded phase to a plaintext at the message scale is the
//!   existing decode step; this module returns the reconstructed flooded value.
//! - Wiring this into the multi-block production decrypt path (replacing the
//!   upstream noiseflood combine, which generates its own mask at the session
//!   degree) is the integration step and rides the degree-decoupled key.

use anyhow::{bail, Result};

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use algebra::sharing::shamir::{RevealOp, ShamirSharings};
use algebra::sharing::share::Share;

use crate::mask_supply::SealedMaskBatch;
use crate::EXTENSION_DEGREE;

/// The ring partials and mask shares live over.
type Ring = ResiduePoly<Z128, EXTENSION_DEGREE>;

/// Reed–Solomon error tolerance for reconstructing a degree-`degree` sharing
/// from `parties` received shares: `⌊(parties − degree − 1)/2⌋`. Zero when the
/// committee is only just large enough to reconstruct at all.
pub fn rs_tolerance(parties: usize, degree: usize) -> usize {
    parties.saturating_sub(degree + 1) / 2
}

/// Add the sealed mask to per-party partial-decryption shares and reconstruct
/// the flooded phase at the key's degree, tolerating up to the Reed–Solomon
/// bound of faulty or missing partials.
///
/// `partials` holds party `j`'s partial `b - ⟨a, s_j⟩` for one ciphertext
/// block, a share over the degree-`degree` key sharing. `mask` supplies party
/// `j`'s share of the summed flooding mask at the same degree and on the same
/// evaluation points. Their share-wise sum is a degree-`degree` sharing of
/// `phase + mask`; reconstructing it yields the flooded phase.
///
/// Errors if the mask's degree does not match `degree`, if a partial has no
/// matching mask share (or vice versa), or if reconstruction fails (more faults
/// than the RS bound).
pub fn degree_aware_flooded_open(
    partials: &[Share<Ring>],
    mask: &SealedMaskBatch,
    degree: usize,
) -> Result<Ring> {
    if mask.degree() != degree {
        bail!(
            "mask degree {} does not match reconstruction degree {degree}",
            mask.degree()
        );
    }
    let mask_shares = mask.mask_shares();
    if partials.len() != mask_shares.len() {
        bail!(
            "{} partials but {} mask shares — one mask share per contributing party is required",
            partials.len(),
            mask_shares.len()
        );
    }

    // Match each partial to its party's mask share and add. Both are indexed by
    // Role; look the mask share up by owner rather than assuming a shared order.
    let mut flooded: Vec<Share<Ring>> = Vec::with_capacity(partials.len());
    for p in partials {
        let m = mask_shares
            .iter()
            .find(|m| m.owner() == p.owner())
            .ok_or_else(|| anyhow::anyhow!("no mask share for party {}", p.owner()))?;
        flooded.push(Share::new(p.owner(), p.value() + m.value()));
    }

    let parties = flooded.len();
    let sharing = ShamirSharings::create(flooded);
    sharing
        .error_reconstruct(degree, rs_tolerance(parties, degree))
        .map_err(|e| anyhow::anyhow!("flooded reconstruction failed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use algebra::sharing::shamir::InputOp;
    use algebra::structure_traits::FromU128;
    use rand::SeedableRng;
    use threshold_types::role::Role;

    use crate::mask_supply::{build_honest_batch, MaskBatchBuilder, MaskContribution};

    const PARTIES: usize = 8;
    const DEGREE: usize = 3; // RS tolerance = (8 - 3 - 1)/2 = 2

    #[test]
    fn tolerance_is_the_reed_solomon_bound() {
        assert_eq!(rs_tolerance(8, 3), 2);
        assert_eq!(rs_tolerance(100, 78), 10);
        // Degenerate: only just reconstructible, zero fault tolerance.
        assert_eq!(rs_tolerance(4, 3), 0);
        // Infeasible geometry saturates to zero rather than underflowing.
        assert_eq!(rs_tolerance(3, 3), 0);
    }

    /// Deal a degree-`DEGREE` sharing of `phase` as stand-in partials.
    fn synthetic_partials(rng: &mut AesRng, phase: Ring) -> Vec<Share<Ring>> {
        ShamirSharings::share(rng, phase, PARTIES, DEGREE)
            .unwrap()
            .shares
    }

    #[test]
    fn flooded_open_recovers_phase_plus_mask() {
        let mut rng = AesRng::seed_from_u64(10);
        let phase = Ring::from_u128(0x1234_5678_9abc_def0);
        let partials = synthetic_partials(&mut rng, phase);

        let mask = build_honest_batch(PARTIES, DEGREE, DEGREE + 1).unwrap();
        // Reconstruct the mask on its own so we know what was added.
        let mask_total = ShamirSharings {
            shares: mask.mask_shares().to_vec(),
        }
        .reconstruct(DEGREE)
        .unwrap();

        let opened = degree_aware_flooded_open(&partials, &mask, DEGREE).unwrap();
        assert_eq!(opened, phase + mask_total);
    }

    #[test]
    fn flooded_open_tolerates_up_to_the_rs_bound_of_faults() {
        let mut rng = AesRng::seed_from_u64(11);
        let phase = Ring::from_u128(42);
        let mut partials = synthetic_partials(&mut rng, phase);
        let mask = build_honest_batch(PARTIES, DEGREE, DEGREE + 1).unwrap();
        let mask_total = ShamirSharings {
            shares: mask.mask_shares().to_vec(),
        }
        .reconstruct(DEGREE)
        .unwrap();

        // Corrupt exactly rs_tolerance = 2 partials; reconstruction must still
        // recover phase + mask.
        let t = rs_tolerance(PARTIES, DEGREE);
        for p in partials.iter_mut().take(t) {
            *p = Share::new(p.owner(), p.value() + Ring::from_u128(0xdead_beef));
        }
        let opened = degree_aware_flooded_open(&partials, &mask, DEGREE).unwrap();
        assert_eq!(opened, phase + mask_total);
    }

    #[test]
    fn flooded_open_rejects_a_degree_mismatch() {
        let mut rng = AesRng::seed_from_u64(12);
        let partials = synthetic_partials(&mut rng, Ring::from_u128(7));
        let mask = build_honest_batch(PARTIES, DEGREE, DEGREE + 1).unwrap();
        // Reconstruct at a different degree than the mask was born at.
        let err = degree_aware_flooded_open(&partials, &mask, DEGREE + 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("mask degree"), "{err}");
    }

    #[test]
    fn flooded_open_rejects_a_party_count_mismatch() {
        let mut rng = AesRng::seed_from_u64(13);
        // Deal partials among fewer parties than the mask was shared to.
        let short = ShamirSharings::share(&mut rng, Ring::from_u128(1), PARTIES - 1, DEGREE)
            .unwrap()
            .shares;
        let mask = build_honest_batch(PARTIES, DEGREE, DEGREE + 1).unwrap();
        let err = degree_aware_flooded_open(&short, &mask, DEGREE)
            .unwrap_err()
            .to_string();
        assert!(err.contains("mask shares"), "{err}");
    }

    #[test]
    fn mask_actually_floods_the_phase() {
        // Sanity: the opened value is the phase shifted by the mask, so the raw
        // phase is not revealed by the opened value alone (the property flooding
        // provides). With overwhelming probability the mask is non-zero.
        let mut rng = AesRng::seed_from_u64(14);
        let phase = Ring::from_u128(0);
        let partials = synthetic_partials(&mut rng, phase);
        let mut builder = MaskBatchBuilder::new(PARTIES, DEGREE);
        for seat in 1..=(DEGREE + 1) {
            let c = MaskContribution::sample_and_deal(
                &mut rng,
                Role::indexed_from_one(seat),
                PARTIES,
                DEGREE,
            )
            .unwrap();
            builder.add(c).unwrap();
        }
        let mask = builder.seal().unwrap();
        let opened = degree_aware_flooded_open(&partials, &mask, DEGREE).unwrap();
        assert_ne!(opened, phase, "mask should shift a zero phase off zero");
    }
}
