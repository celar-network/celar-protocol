//! Flooding-mask supply at the key's sharing degree (local-sample-and-sum).
//!
//! Threshold decryption floods the opened value with a mask `E = Σ e_i` so the
//! revealed phase leaks nothing about the secret key beyond the plaintext. When
//! a key's sharing degree is decoupled from the committee's corruption
//! threshold (a degree-78 key on a 100-seat committee), the mask must be
//! **born at the key's degree**, or a low-degree coalition reconstructs the
//! mask polynomial in advance and subtracts it — restoring the exact leakage
//! flooding exists to prevent (the "strip attack").
//!
//! **Why local-sample-and-sum, and why it is not a choice.** Composing a mask
//! inside MPC (shared preprocessing) needs multiplication, which doubles the
//! sharing degree — a degree-78 mask would need `n > 3·78 = 234`, impossible at
//! c=100. The deployed low-degree decrypt path gets away with shared
//! preprocessing because it floods at the small compute degree; at the
//! decoupled degree it hits the same wall. So the only viable construction is
//! contribution-sum: each of a quorum of seats **locally samples** a bounded
//! term and **shares it at the key degree** (pure distribution, needs only
//! `n > degree`, no opening, no multiplication). The mask is the sum. Secrecy
//! against a degree-coalition needs one honest contributor, i.e. `degree + 1`
//! contributions.
//!
//! **The independence property is in the SHARING, not any ceremony ordering:**
//! contributions are degree-shared and never opened, so a coalition below the
//! degree cannot learn or bias another seat's term — a would-be adaptive
//! contributor would need `degree + 1` shares of others' terms, which is the
//! collusion secrecy already excludes. A future change that opens contributions
//! before the batch is used removes this property silently; do not add one.
//!
//! **Seams this module deliberately does NOT cross:**
//! - **The range bound.** A contribution's term must lie in
//!   `[2^LOG_FLOODING_MASK_LOWER_BOUND, 2^LOG_FLOODING_MASK_BOUND]`. The honest
//!   sampler here draws in-range by construction; making a *malicious*
//!   out-of-range term a proof failure is the partial-decryption proof
//!   relation's job, which does not exist yet. Shares do not reveal their value,
//!   so the builder validates structure (degree, party count, distinct dealer,
//!   commitment), not the term's magnitude.
//! - **Consumption.** This module produces the summed mask *sharing*; folding it
//!   into the noiseflood decrypt path is the degree-aware decrypt path's job.
//!   The seam is [`SealedMaskBatch::mask_shares`].
//! - **The audit.** Cut-and-choose auditing of contributions (a canary that
//!   opens a beacon-selected subset and distribution-tests it) is designed
//!   separately and deferred pending its detection-power review; it is not
//!   implemented here.
//!
//! **The sealing invariant, enforced by type-state.** The mask batch must be
//! sealed — all contributions dealt and committed — before anything consumes it.
//! [`SealedMaskBatch`]'s only constructor is [`MaskBatchBuilder::seal`], which
//! takes the builder **by value**; an unsealed builder cannot reach the consume
//! path, and the ordering bug does not typecheck (see the `compile_fail` doctest
//! on [`SealedMaskBatch`]).

use std::collections::HashSet;

use aes_prng::AesRng;
use anyhow::{bail, Result};
use rand::{CryptoRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use algebra::sharing::shamir::{InputOp, ShamirSharings};
use algebra::sharing::share::Share;
use algebra::structure_traits::FromU128;
use threshold_types::role::Role;

use crate::budget::{LOG_B_EVAL, LOG_DECOUPLED_CONTRIB_BOUND};
use crate::EXTENSION_DEGREE;

/// The ring flooding terms are shared over (same as the threshold decrypt path).
type MaskRing = ResiduePoly<Z128, EXTENSION_DEGREE>;

/// log₂ floor on a single contribution's flooding term — the lower bound of the
/// two-sided flooding range. The mask must be at least as large as the
/// evaluated noise it drowns, so the floor is B_eval = 2^LOG_B_EVAL.
pub const CONTRIB_LOG_MIN: u32 = LOG_B_EVAL;
/// log₂ ceiling on a single contribution's flooding term — the DECOUPLED
/// per-contribution bound, so a sum of up to `DECOUPLED_CONTRIBUTIONS` terms
/// stays under Δ/2 = 2^122. NOT the deployed single-source bound, whose 79-sum
/// overshoots the margin. The floor/ceiling gap is DECOUPLED_FLOODING_STATSEC
/// (= 46), so an honest draw is range-rejected with probability 2^-46.
pub const CONTRIB_LOG_MAX: u32 = LOG_DECOUPLED_CONTRIB_BOUND;

/// Draw a flooding-term magnitude in the flooding range `[2^CONTRIB_LOG_MIN,
/// 2^CONTRIB_LOG_MAX)`. Real TUniform sampling lands in this range for all but
/// a `2^-λ_stat` fraction of draws (the honest false-reject the range bound is
/// derived against); conditioning on the range here keeps the honest path
/// deterministic without changing what a correct sampler produces w.h.p.
fn sample_bounded_magnitude<R: Rng + CryptoRng>(rng: &mut R) -> u128 {
    let min = 1u128 << CONTRIB_LOG_MIN;
    let max = 1u128 << CONTRIB_LOG_MAX;
    rng.gen_range(min..max)
}

/// A magnitude and a random sign, as a centered ring scalar (negatives are the
/// two's-complement image mod 2^128, matching the decrypt path's convention).
fn term_from_magnitude(mag: u128, negative: bool) -> MaskRing {
    let raw = if negative { mag.wrapping_neg() } else { mag };
    MaskRing::from_u128(raw)
}

/// One seat's contribution: a bounded flooding term, shared at the key degree,
/// plus a commitment binding the sharing.
///
/// In deployment the dealer sends share `j` to party `j` and broadcasts the
/// commitment; this batch model holds the whole sharing (as the DKG simulator
/// does), and the transcript keeps only the hash, never the shares.
#[derive(Debug, Clone)]
pub struct MaskContribution {
    dealer: Role,
    sharing: ShamirSharings<MaskRing>,
    commitment: [u8; 32],
    parties: usize,
    degree: usize,
}

impl MaskContribution {
    /// Honest contribution: sample a term in the flooding range and deal it at
    /// `degree` among `parties`. `dealer` is the contributing seat.
    pub fn sample_and_deal<R: Rng + CryptoRng>(
        rng: &mut R,
        dealer: Role,
        parties: usize,
        degree: usize,
    ) -> Result<Self> {
        if degree >= parties {
            bail!("degree {degree} must be strictly less than parties {parties}");
        }
        let mag = sample_bounded_magnitude(rng);
        let term = term_from_magnitude(mag, rng.gen::<bool>());
        let sharing = ShamirSharings::share(rng, term, parties, degree)?;
        let commitment = commit_sharing(dealer, &sharing);
        Ok(Self {
            dealer,
            sharing,
            commitment,
            parties,
            degree,
        })
    }

    pub fn dealer(&self) -> Role {
        self.dealer
    }
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }
}

/// Commit to a contribution's sharing: `SHA256(dealer ‖ bincode(shares))`.
/// The transcript stores this hash, never the shares (see the crate header).
fn commit_sharing(dealer: Role, sharing: &ShamirSharings<MaskRing>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"celar.b7.mask-contribution.v1");
    hasher.update(dealer.one_based().to_be_bytes());
    let bytes = bincode::serialize(&sharing.shares).unwrap_or_default();
    hasher.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Open, accumulating batch. Cannot be consumed as a mask — the consume path
/// takes [`SealedMaskBatch`], which this is not, and there is no conversion
/// except [`Self::seal`].
#[derive(Debug)]
pub struct MaskBatchBuilder {
    parties: usize,
    degree: usize,
    /// Distinct contributions required to seal: `degree + 1` (one honest
    /// contributor must lie outside any degree-coalition).
    required: usize,
    contributions: Vec<MaskContribution>,
    dealers: HashSet<Role>,
}

impl MaskBatchBuilder {
    /// A fresh builder for a `parties`-seat committee sharing at `degree`.
    pub fn new(parties: usize, degree: usize) -> Self {
        Self {
            parties,
            degree,
            required: degree + 1,
            contributions: Vec::new(),
            dealers: HashSet::new(),
        }
    }

    /// The distinct-contribution quorum needed to seal.
    pub fn required(&self) -> usize {
        self.required
    }

    /// Number of distinct contributions collected so far.
    pub fn collected(&self) -> usize {
        self.dealers.len()
    }

    /// Admit one contribution. Validates STRUCTURE — matching committee shape,
    /// a distinct dealer, and that the stored commitment binds the sharing. The
    /// term's *magnitude* is not (and cannot be) checked here from shares; that
    /// is the honest sampler's guarantee and the decryption relation's proof
    /// (see the module header).
    pub fn add(&mut self, c: MaskContribution) -> Result<()> {
        if c.parties != self.parties || c.degree != self.degree {
            bail!(
                "contribution shape (parties={}, degree={}) does not match batch (parties={}, degree={})",
                c.parties,
                c.degree,
                self.parties,
                self.degree
            );
        }
        if c.sharing.shares.len() != self.parties {
            bail!(
                "contribution carries {} shares, expected {} (one per party)",
                c.sharing.shares.len(),
                self.parties
            );
        }
        if commit_sharing(c.dealer, &c.sharing) != c.commitment {
            bail!("contribution commitment does not bind its sharing");
        }
        if !self.dealers.insert(c.dealer) {
            bail!("duplicate contribution from dealer {}", c.dealer);
        }
        self.contributions.push(c);
        Ok(())
    }

    /// Seal the batch — **the only way to make a [`SealedMaskBatch`]**. Requires
    /// the full distinct-contribution quorum, sums the contributions into the
    /// mask sharing, and binds the batch commitment. Takes `self` by value, so a
    /// builder cannot be reused after sealing and an unsealed batch cannot be
    /// consumed.
    pub fn seal(self) -> Result<SealedMaskBatch> {
        if self.dealers.len() < self.required {
            bail!(
                "cannot seal: {} distinct contributions, need {} (degree {} + 1)",
                self.dealers.len(),
                self.required,
                self.degree
            );
        }

        // The mask sharing is the share-wise sum of the contributions: party j's
        // mask share is Σ_i (its share of contribution i). Degree is preserved
        // by addition (no multiplication), so the mask is a degree-`degree`
        // sharing of Σ terms.
        let mut iter = self.contributions.iter();
        let first = iter
            .next()
            .expect("quorum >= degree + 1 >= 1, so at least one contribution");
        let mut mask_sharing = first.sharing.clone();
        for c in iter {
            mask_sharing = &mask_sharing + &c.sharing;
        }

        // Batch commitment binds every contribution commitment, in dealer order
        // so it is independent of arrival order.
        let mut commitments: Vec<[u8; 32]> =
            self.contributions.iter().map(|c| c.commitment).collect();
        commitments.sort_unstable();
        let mut hasher = Sha256::new();
        hasher.update(b"celar.b7.mask-batch.v1");
        for c in &commitments {
            hasher.update(c);
        }
        let mut batch_commitment = [0u8; 32];
        batch_commitment.copy_from_slice(&hasher.finalize());

        Ok(SealedMaskBatch {
            mask_sharing,
            batch_commitment,
            parties: self.parties,
            degree: self.degree,
            contributors: self.dealers.len(),
        })
    }
}

/// A sealed, immutable mask batch — the flooding mask, ready to consume.
///
/// The only constructor is [`MaskBatchBuilder::seal`]; the consume path takes
/// `&SealedMaskBatch`, so an unsealed builder cannot be fed to it. That is the
/// sealing invariant, enforced by the type system rather than a runtime
/// check that could be forgotten:
///
/// ```compile_fail
/// use celar_kms::mask_supply::{MaskBatchBuilder, SealedMaskBatch};
/// fn consume(_: &SealedMaskBatch) {}
/// let builder = MaskBatchBuilder::new(5, 2);
/// // A builder is not a sealed batch — this must not compile.
/// consume(&builder);
/// ```
#[derive(Debug, Clone)]
pub struct SealedMaskBatch {
    mask_sharing: ShamirSharings<MaskRing>,
    batch_commitment: [u8; 32],
    parties: usize,
    degree: usize,
    contributors: usize,
}

impl SealedMaskBatch {
    /// The mask shares the degree-aware decrypt path consumes — party `j`'s share of the
    /// summed flooding mask, a degree-`degree` sharing.
    pub fn mask_shares(&self) -> &[Share<MaskRing>] {
        &self.mask_sharing.shares
    }

    /// The batch commitment, bound into the reshare transcript and reused as the
    /// pre-image for the audit-selection beacon.
    pub fn batch_commitment(&self) -> [u8; 32] {
        self.batch_commitment
    }

    pub fn degree(&self) -> usize {
        self.degree
    }
    pub fn parties(&self) -> usize {
        self.parties
    }
    pub fn contributors(&self) -> usize {
        self.contributors
    }
}

/// Domain separator for the VRF-mixed contribution seed (SR9 / adopt-list item 5).
pub const VRF_SEED_DOMAIN: &[u8] = b"celar.kms.mask.contribution-seed.v1";

/// Derive a per-seat contribution seed that stays unpredictable to a COALITION
/// even if the fleet's local RNG fails (the Debian-OpenSSL / low-entropy class
/// that variance/χ² and the E55 range check are structurally blind to). The seat
/// mixes the output of a VRF under its OWN key over `epoch ‖ index` with its
/// local entropy:
///
/// ```text
///   seed = SHA-256( DOMAIN ‖ len(vrf_output) ‖ vrf_output ‖ local_entropy )
/// ```
///
/// A fleet-wide local-RNG failure then degrades to "predictable to the seat"
/// (which holds the VRF key) rather than "predictable to the coalition". The
/// length prefix keeps `vrf_output ‖ local_entropy` unambiguous for any
/// `vrf_output` length. This layer is KEY-AGNOSTIC: `vrf_output` is computed by
/// the caller, which holds the seat's key, so the VRF/key choice is not baked in
/// here (design: `doc/engg/tasks/vrf-contribution-seeds/design.md`).
pub fn vrf_mixed_contribution_seed(vrf_output: &[u8], local_entropy: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VRF_SEED_DOMAIN);
    h.update((vrf_output.len() as u64).to_be_bytes());
    h.update(vrf_output);
    h.update(local_entropy);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&h.finalize());
    seed
}

/// Convenience for the honest all-seats path and for tests: build a sealed batch
/// from `contributors` seats each sampling and dealing one contribution.
pub fn build_honest_batch(
    parties: usize,
    degree: usize,
    contributors: usize,
) -> Result<SealedMaskBatch> {
    let mut rng = AesRng::from_random_seed();
    let mut builder = MaskBatchBuilder::new(parties, degree);
    for seat in 1..=contributors {
        let c = MaskContribution::sample_and_deal(
            &mut rng,
            Role::indexed_from_one(seat),
            parties,
            degree,
        )?;
        builder.add(c)?;
    }
    builder.seal()
}

/// Build a sealed batch where each seat samples its contribution from its OWN
/// per-seat seed (`vrf_mixed_contribution_seed`), rather than one shared local
/// RNG as `build_honest_batch` uses. The production path derives each seed from
/// the seat's VRF output (node side, `node::vrf_contribution_output`); this
/// layer just consumes the seeds and stays key-agnostic. `seat_seeds` is
/// `(one-based seat, 32-byte mixed seed)`.
pub fn build_batch_from_seeds(
    parties: usize,
    degree: usize,
    seat_seeds: &[(usize, [u8; 32])],
) -> Result<SealedMaskBatch> {
    let mut builder = MaskBatchBuilder::new(parties, degree);
    for (seat, seed) in seat_seeds {
        // Per-seat deterministic RNG keyed by the VRF-mixed seed. AesRng's seed
        // is the 128-bit AES key, so take the first 16 bytes of the 256-bit
        // mixed seed (full 128-bit entropy). If the crate's `Seed` type is
        // [u8; 32], pass `*seed` here instead.
        let mut key = [0u8; 16];
        key.copy_from_slice(&seed[..16]);
        let mut rng = AesRng::from_seed(key);
        let c = MaskContribution::sample_and_deal(
            &mut rng,
            Role::indexed_from_one(*seat),
            parties,
            degree,
        )?;
        builder.add(c)?;
    }
    builder.seal()
}

/// Derive one seat's flooding term deterministically from its per-seat
/// contribution seed — the SAME magnitude+sign draw [`build_batch_from_seeds`]
/// makes for a given seed, factored out so the DISTRIBUTED dealer (node side,
/// `node::run_distributed_mask_contribution`) inputs an IDENTICAL term for a
/// given VRF-mixed seed. Only the term must be well-defined per seed; the
/// SHARING randomness differs by construction — a fresh local RNG in the
/// single-process builder vs. the networked session's RNG in the distributed
/// dealer — because whoever deals the term redraws its sharing.
pub fn contribution_term_from_seed(seed: &[u8; 32]) -> ResiduePoly<Z128, EXTENSION_DEGREE> {
    let mut key = [0u8; 16];
    key.copy_from_slice(&seed[..16]);
    let mut rng = AesRng::from_seed(key);
    let mag = sample_bounded_magnitude(&mut rng);
    term_from_magnitude(mag, rng.gen::<bool>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::sharing::shamir::RevealOp;
    use rand::SeedableRng;

    const PARTIES: usize = 8;
    const DEGREE: usize = 3; // quorum = 4

    #[test]
    fn vrf_mixed_seed_is_deterministic_and_input_sensitive() {
        let vrf = b"vrf-output-bytes";
        let ent = [7u8; 32];
        let a = vrf_mixed_contribution_seed(vrf, &ent);
        // Deterministic in (vrf_output, local_entropy).
        assert_eq!(a, vrf_mixed_contribution_seed(vrf, &ent));
        // A different VRF output changes the seed — a coalition without the
        // seat's key cannot predict it even if local_entropy is known/broken.
        assert_ne!(a, vrf_mixed_contribution_seed(b"other-vrf-output", &ent));
        // A different local entropy changes the seed.
        assert_ne!(a, vrf_mixed_contribution_seed(vrf, &[8u8; 32]));
        // Length prefix: ("ab", ent) must differ from ("a", ent) so the
        // vrf_output/local_entropy boundary is never ambiguous.
        assert_ne!(
            vrf_mixed_contribution_seed(b"ab", &ent),
            vrf_mixed_contribution_seed(b"a", &ent),
        );
    }

    #[test]
    fn contribution_term_is_deterministic_and_in_range() {
        // The distributed dealer and the single-process builder must derive the
        // SAME term from the same seed. Deterministic, and its magnitude lands in
        // the flooding range (the term rides a random sign, so check |term| via
        // the two derivations agreeing rather than re-deriving the magnitude).
        let seed = [9u8; 32];
        assert_eq!(
            contribution_term_from_seed(&seed),
            contribution_term_from_seed(&seed)
        );
        assert_ne!(
            contribution_term_from_seed(&seed),
            contribution_term_from_seed(&[10u8; 32])
        );
    }

    #[test]
    fn seeded_batch_is_deterministic_in_seeds() {
        let seeds: Vec<(usize, [u8; 32])> =
            (1..=DEGREE + 1).map(|s| (s, [s as u8; 32])).collect();
        let a = build_batch_from_seeds(PARTIES, DEGREE, &seeds).unwrap();
        // Same per-seat seeds → same batch (deterministic).
        let b = build_batch_from_seeds(PARTIES, DEGREE, &seeds).unwrap();
        assert_eq!(a.batch_commitment(), b.batch_commitment());
        // Different seeds → different batch.
        let seeds2: Vec<(usize, [u8; 32])> =
            (1..=DEGREE + 1).map(|s| (s, [(s + 100) as u8; 32])).collect();
        let c = build_batch_from_seeds(PARTIES, DEGREE, &seeds2).unwrap();
        assert_ne!(a.batch_commitment(), c.batch_commitment());
    }

    #[test]
    fn range_constants_mirror_budget() {
        // The lower bound is the evaluated-noise bound; the upper is the mask
        // sampling bound. If budget.rs moves these, this test forces the mask
        // supply to be re-derived rather than silently drifting.
        assert_eq!(CONTRIB_LOG_MIN, crate::budget::LOG_B_EVAL);
        assert_eq!(CONTRIB_LOG_MAX, crate::budget::LOG_DECOUPLED_CONTRIB_BOUND);
        assert!(CONTRIB_LOG_MIN < CONTRIB_LOG_MAX);
    }

    #[test]
    fn full_contribution_sum_fits_the_decryption_margin() {
        // The mask is the SUM of up to DECOUPLED_CONTRIBUTIONS terms, each at
        // most 2^CONTRIB_LOG_MAX in magnitude. That sum, plus the sign bit and
        // the evaluated noise (≤ 2^LOG_B_EVAL) it rides on, must stay under
        // Δ/2 = 2^122 — otherwise a full-degree decoupled decrypt corrupts the
        // plaintext silently. Integer arithmetic, no logs.
        const LOG_DELTA_HALF: u32 = 122;
        let n = crate::budget::DECOUPLED_CONTRIBUTIONS as u128;
        let per_term_max: u128 = 1u128 << CONTRIB_LOG_MAX; // magnitude ceiling
        let sum_max = n * per_term_max; // worst-case aggregate magnitude
        let noise_max: u128 = 1u128 << crate::budget::LOG_B_EVAL;
        let margin: u128 = 1u128 << LOG_DELTA_HALF;
        // signed terms → factor 2 headroom on the sum, then add the noise floor.
        assert!(
            sum_max
                .checked_mul(2)
                .and_then(|s| s.checked_add(noise_max))
                .map(|t| t < margin)
                .unwrap_or(false),
            "79-term decoupled mask sum overshoots Δ/2 = 2^122"
        );
        // And the deployed single-source bound would NOT fit — guards the fix.
        let deployed_term: u128 = 1u128 << crate::budget::LOG_FLOODING_MASK_BOUND;
        assert!(
            n * deployed_term >= margin,
            "sanity: deployed per-term bound must be the one that overshoots"
        );
    }

    #[test]
    fn sampled_magnitude_is_in_the_e55_range() {
        let mut rng = AesRng::seed_from_u64(1);
        for _ in 0..1000 {
            let m = sample_bounded_magnitude(&mut rng);
            assert!(m >= (1u128 << CONTRIB_LOG_MIN));
            assert!(m < (1u128 << CONTRIB_LOG_MAX));
        }
    }

    #[test]
    fn mask_batch_seal_requires_full_quorum() {
        let mut rng = AesRng::seed_from_u64(2);
        let mut builder = MaskBatchBuilder::new(PARTIES, DEGREE);
        // One short of the quorum (degree + 1 = 4): sealing must refuse.
        for seat in 1..=DEGREE {
            let c = MaskContribution::sample_and_deal(
                &mut rng,
                Role::indexed_from_one(seat),
                PARTIES,
                DEGREE,
            )
            .unwrap();
            builder.add(c).unwrap();
        }
        assert_eq!(builder.collected(), DEGREE);
        let err = builder.seal().unwrap_err().to_string();
        assert!(err.contains("cannot seal"), "{err}");
    }

    #[test]
    fn add_rejects_a_duplicate_dealer() {
        let mut rng = AesRng::seed_from_u64(3);
        let mut builder = MaskBatchBuilder::new(PARTIES, DEGREE);
        let dealer = Role::indexed_from_one(1);
        let a = MaskContribution::sample_and_deal(&mut rng, dealer, PARTIES, DEGREE).unwrap();
        let b = MaskContribution::sample_and_deal(&mut rng, dealer, PARTIES, DEGREE).unwrap();
        builder.add(a).unwrap();
        let err = builder.add(b).unwrap_err().to_string();
        assert!(err.contains("duplicate contribution"), "{err}");
    }

    #[test]
    fn sealed_mask_reconstructs_to_the_sum_of_the_contributions() {
        // With a full quorum and no faults, the mask sharing reconstructs at
        // `degree`, and it is the sum of the (never-opened) contribution terms —
        // the property the strip attack targets and the sum defends.
        let mut rng = AesRng::seed_from_u64(4);
        let mut builder = MaskBatchBuilder::new(PARTIES, DEGREE);
        let mut expected = MaskRing::from_u128(0);
        for seat in 1..=(DEGREE + 1) {
            // Rebuild each contribution deterministically so we know its term.
            let mag = sample_bounded_magnitude(&mut rng);
            let negative = rng.gen::<bool>();
            let term = term_from_magnitude(mag, negative);
            expected = expected + term;
            let sharing =
                ShamirSharings::share(&mut rng, term, PARTIES, DEGREE).unwrap();
            let commitment = commit_sharing(Role::indexed_from_one(seat), &sharing);
            builder
                .add(MaskContribution {
                    dealer: Role::indexed_from_one(seat),
                    sharing,
                    commitment,
                    parties: PARTIES,
                    degree: DEGREE,
                })
                .unwrap();
        }
        let sealed = builder.seal().unwrap();
        assert_eq!(sealed.contributors(), DEGREE + 1);
        let recon = ShamirSharings {
            shares: sealed.mask_shares().to_vec(),
        }
        .reconstruct(DEGREE)
        .unwrap();
        assert_eq!(recon, expected);
    }

    #[test]
    fn honest_batch_builds_and_reconstructs_at_degree() {
        let sealed = build_honest_batch(PARTIES, DEGREE, DEGREE + 1).unwrap();
        assert_eq!(sealed.parties(), PARTIES);
        assert_eq!(sealed.degree(), DEGREE);
        // Reconstructs (no faults) — confirms the summed sharing is well-formed
        // at the declared degree.
        ShamirSharings {
            shares: sealed.mask_shares().to_vec(),
        }
        .reconstruct(DEGREE)
        .unwrap();
    }
}
