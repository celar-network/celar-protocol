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

use threshold_execution::endpoints::decryption::{
    combine_plaintext_blocks, partial_decrypt128, BlocksPartialDecrypt, SnsDecryptionKeyType,
    SnsRadixOrBoolCiphertext,
};
use threshold_execution::endpoints::reconstruct::reconstruct_message;
use threshold_execution::runtime::sessions::base_session::BaseSessionHandles;
use threshold_execution::sharing::open::{RobustOpen, SecureRobustOpen};
use threshold_execution::tfhe_internals::parameters::AugmentedCiphertextParameters;
use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;
use threshold_types::role::Role;

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

/// Decrypt a switch-and-squashed ciphertext against a key shared at `degree`,
/// flooding with the degree-`degree` sealed mask — the degree-decoupled
/// analogue of the upstream noiseflood combine, which masks and reconstructs at
/// the session degree instead. LOCAL: it takes EVERY party's key share and
/// computes their partials in one process, so the whole degree-aware path can
/// be exercised end to end without a live committee. One `masks` entry per
/// ciphertext block (each block floods with an independent mask).
///
/// Per block: each party's [`partial_decrypt128`] yields its share of the phase
/// `b − ⟨a, s_j⟩` over the degree-`degree` key sharing; [`degree_aware_flooded_open`]
/// adds that party's mask share and reconstructs the flooded phase at `degree`
/// (tolerating the Reed–Solomon bound of faults); [`reconstruct_message`] maps
/// the opened phase down to the block's message space; [`combine_plaintext_blocks`]
/// recomposes the u64 plaintext. Reuses the upstream partial-decrypt and decode
/// unchanged — only the mask-and-reconstruct middle is degree-aware.
pub fn decrypt_decoupled_local(
    sk_shares: &[PrivateKeySet<EXTENSION_DEGREE>],
    roles: &[Role],
    ct: &SnsRadixOrBoolCiphertext,
    masks: &[SealedMaskBatch],
    degree: usize,
    ddec_key_type: SnsDecryptionKeyType,
) -> Result<u64> {
    if sk_shares.len() != roles.len() {
        bail!(
            "{} key shares but {} roles — one share per contributing party",
            sk_shares.len(),
            roles.len()
        );
    }
    let blocks: Vec<_> = ct.packed_blocks().collect();
    if masks.len() != blocks.len() {
        bail!(
            "{} sealed masks but {} ciphertext blocks — one mask per block",
            masks.len(),
            blocks.len()
        );
    }

    // Per block: assemble each party's phase share, then open-and-flood at the
    // key's degree.
    let mut opened: Vec<Ring> = Vec::with_capacity(blocks.len());
    for (block, mask) in blocks.iter().zip(masks) {
        let mut partials: Vec<Share<Ring>> = Vec::with_capacity(roles.len());
        for (role, sk) in roles.iter().zip(sk_shares) {
            let phase = partial_decrypt128(sk, block, ddec_key_type)?;
            partials.push(Share::new(*role, phase));
        }
        opened.push(degree_aware_flooded_open(&partials, mask, degree)?);
    }

    // Map opened flooded phases → message-space scalars → u64, exactly as the
    // upstream combine does after its own open.
    let params = &sk_shares[0].parameters;
    let scalars = reconstruct_message(Some(opened), params)?;
    let bits_in_block = ct.packing_factor() * params.message_modulus_log() as usize;
    combine_plaintext_blocks::<u64>(BlocksPartialDecrypt {
        bits_in_block: bits_in_block as u32,
        partial_decryptions: scalars,
    })
}

/// Distributed degree-aware threshold decrypt — the production shape. Each party
/// runs this with its OWN key share and its shares of the per-block flooding
/// masks; reconstruction is a network robust-open **at the key's degree**, not
/// the session threshold, which is the whole point of decoupling. This replaces
/// the upstream noiseflood combine (session-degree mask + session-degree open)
/// with the degree-`degree` sealed mask + degree-`degree` open, reusing
/// [`partial_decrypt128`] and the decode path unchanged.
///
/// `my_mask_shares` holds this party's share of each block's degree-`degree`
/// flooding mask (one per packed block), from [`crate::mask_supply`].
pub async fn run_degree_aware_decrypt<S>(
    session: &S,
    share: &PrivateKeySet<EXTENSION_DEGREE>,
    my_mask_shares: &[Share<Ring>],
    ct: &SnsRadixOrBoolCiphertext,
    degree: usize,
    ddec_key_type: SnsDecryptionKeyType,
) -> Result<u64>
where
    S: BaseSessionHandles,
{
    let blocks: Vec<_> = ct.packed_blocks().collect();
    if my_mask_shares.len() != blocks.len() {
        bail!(
            "{} mask shares but {} ciphertext blocks — one mask share per block",
            my_mask_shares.len(),
            blocks.len()
        );
    }

    // Per block: this party's phase share `b − ⟨a, s_j⟩` plus its share of the
    // degree-`degree` flooding mask.
    let mut masked: Vec<Ring> = Vec::with_capacity(blocks.len());
    for (block, mask_share) in blocks.iter().zip(my_mask_shares) {
        let phase = partial_decrypt128(share, block, ddec_key_type)?;
        masked.push(phase + mask_share.value());
    }

    // Network robust-open AT THE KEY'S DEGREE (the decoupled reconstruction),
    // then the upstream decode.
    let opened = SecureRobustOpen::default()
        .robust_open_list_to_all(session, masked, degree)
        .await?;
    let scalars = reconstruct_message(opened, &share.parameters)?;
    let bits_in_block = ct.packing_factor() * share.parameters.message_modulus_log() as usize;
    combine_plaintext_blocks::<u64>(BlocksPartialDecrypt {
        bits_in_block: bits_in_block as u32,
        partial_decryptions: scalars,
    })
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

    #[tokio::test]
    async fn decoupled_decrypt_recovers_a_real_ciphertext() {
        // End-to-end: generate a switch-and-squash keyset SHARED AT DEGREE d in
        // one in-test distributed keygen (insecure keygen at session threshold
        // = d), encrypt a value, then reconstruct at the KEY's degree via the
        // degree-decoupled path — proving the wiring recovers the plaintext
        // against a real key and ciphertext, not just synthetic shares.
        use tfhe::prelude::CiphertextList;
        use threshold_execution::endpoints::decryption::RadixOrBoolCiphertext;
        use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
        use threshold_execution::runtime::sessions::small_session::SmallSession;
        use threshold_execution::tests::helper::tests_and_benches::execute_protocol_small;
        use threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
        use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
        use threshold_execution::tfhe_internals::test_feature::insecure_initialize_key_material;
        use threshold_types::network::NetworkMode;

        const N: usize = 7; // parties
        const D: usize = 3; // key sharing degree — reconstruction happens HERE
        let value: u64 = 42;

        // 1) In-test distributed keygen: an SnS keyset shared at degree D across N.
        let mut task = |mut session: SmallSession<Ring>, _info: Option<String>| async move {
            let role = session.my_role();
            let (pubkeys, my_share) = insecure_initialize_key_material::<_, EXTENSION_DEGREE>(
                &mut session,
                PARAMS_TEST_BK_SNS,
                tfhe::Tag::default(),
            )
            .await
            .unwrap();
            (role, pubkeys, my_share)
        };
        let mut results = execute_protocol_small::<_, _, Ring, EXTENSION_DEGREE>(
            N,
            D as u8,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        )
        .await;
        results.sort_by_key(|(r, _, _)| r.one_based());
        let roles: Vec<Role> = results.iter().map(|(r, _, _)| *r).collect();
        let pk: FhePubKeySet = results[0].1.clone();
        let sk_shares: Vec<_> = results.into_iter().map(|(_, _, sk)| sk).collect();

        // 2) Client side: encrypt under pk_G, then switch-and-squash.
        tfhe::set_server_key(pk.server_key.clone());
        let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
            .push(value)
            .build();
        let expanded = compact.expand().unwrap();
        let ct: tfhe::FheUint64 = expanded.get(0).unwrap().unwrap();
        let (radix, _, _, _) = ct.into_raw_parts();
        let small_ct = RadixOrBoolCiphertext::Radix(radix);
        let int_sk: &tfhe::integer::ServerKey = pk.server_key.as_ref();
        let sns_key = pk.server_key.noise_squashing_key().unwrap();
        let large_ct = match &small_ct {
            RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
                sns_key.squash_radix_ciphertext_noise(int_sk, c).unwrap(),
            ),
            RadixOrBoolCiphertext::Bool(_) => panic!("radix expected"),
        };

        // 3) One independent degree-D flooding mask per packed block.
        let n_blocks = large_ct.packed_blocks().count();
        let masks: Vec<SealedMaskBatch> = (0..n_blocks)
            .map(|_| build_honest_batch(N, D, D + 1).unwrap())
            .collect();

        // 4) Degree-decoupled decrypt and recover.
        let recovered = decrypt_decoupled_local(
            &sk_shares,
            &roles,
            &large_ct,
            &masks,
            D,
            SnsDecryptionKeyType::SnsKey,
        )
        .unwrap();
        assert_eq!(
            recovered, value,
            "degree-decoupled decrypt must recover the plaintext"
        );
    }

    #[tokio::test]
    async fn distributed_decoupled_decrypt_recovers_a_real_ciphertext() {
        // The production shape: a real keyset shared at degree D, then every
        // party runs the DISTRIBUTED degree-aware decrypt (network robust-open
        // at the key's degree) and independently recovers the plaintext.
        use std::sync::Arc;
        use tfhe::prelude::CiphertextList;
        use threshold_execution::endpoints::decryption::RadixOrBoolCiphertext;
        use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
        use threshold_execution::runtime::sessions::small_session::SmallSession;
        use threshold_execution::tests::helper::tests_and_benches::execute_protocol_small;
        use threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
        use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;
        use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
        use threshold_execution::tfhe_internals::test_feature::insecure_initialize_key_material;
        use threshold_types::network::NetworkMode;

        const N: usize = 7;
        const D: usize = 3;
        let value: u64 = 42;

        // Phase 1: distributed keygen — an SnS keyset shared at degree D.
        let mut kg = |mut session: SmallSession<Ring>, _info: Option<String>| async move {
            let role = session.my_role();
            let (pk, sk) = insecure_initialize_key_material::<_, EXTENSION_DEGREE>(
                &mut session,
                PARAMS_TEST_BK_SNS,
                tfhe::Tag::default(),
            )
            .await
            .unwrap();
            (role, pk, sk)
        };
        let mut kg_results = execute_protocol_small::<_, _, Ring, EXTENSION_DEGREE>(
            N,
            D as u8,
            None,
            NetworkMode::Sync,
            None,
            &mut kg,
            None,
        )
        .await;
        kg_results.sort_by_key(|(r, _, _)| r.one_based());
        let pk: FhePubKeySet = kg_results[0].1.clone();

        // Encrypt once + switch-and-squash (client side).
        tfhe::set_server_key(pk.server_key.clone());
        let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
            .push(value)
            .build();
        let expanded = compact.expand().unwrap();
        let ct: tfhe::FheUint64 = expanded.get(0).unwrap().unwrap();
        let (radix, _, _, _) = ct.into_raw_parts();
        let small_ct = RadixOrBoolCiphertext::Radix(radix);
        let int_sk: &tfhe::integer::ServerKey = pk.server_key.as_ref();
        let sns_key = pk.server_key.noise_squashing_key().unwrap();
        let large_ct = match &small_ct {
            RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
                sns_key.squash_radix_ciphertext_noise(int_sk, c).unwrap(),
            ),
            RadixOrBoolCiphertext::Bool(_) => panic!("radix expected"),
        };
        let n_blocks = large_ct.packed_blocks().count();

        // One degree-D flooding mask per block; give each party its shares.
        let mask_batches: Vec<SealedMaskBatch> = (0..n_blocks)
            .map(|_| build_honest_batch(N, D, D + 1).unwrap())
            .collect();
        // Per party, indexed by one-based role: (key share, one mask share per block).
        let mut per_party: Vec<(PrivateKeySet<EXTENSION_DEGREE>, Vec<Share<Ring>>)> =
            Vec::with_capacity(N);
        for (role, _, sk) in kg_results.into_iter() {
            let my_masks: Vec<Share<Ring>> = mask_batches
                .iter()
                .map(|mb| {
                    mb.mask_shares()
                        .iter()
                        .find(|s| s.owner() == role)
                        .unwrap()
                        .clone()
                })
                .collect();
            per_party.push((sk, my_masks));
        }
        let per_party = Arc::new(per_party);
        let large_ct = Arc::new(large_ct);

        // Phase 2: distributed degree-aware decrypt; every party recovers value.
        let mut dec = |session: SmallSession<Ring>, _info: Option<String>| {
            let per_party = per_party.clone();
            let large_ct = large_ct.clone();
            async move {
                let idx = session.my_role().one_based() - 1;
                let (share, masks) = &per_party[idx];
                let pt = run_degree_aware_decrypt(
                    &session,
                    share,
                    masks,
                    &large_ct,
                    D,
                    SnsDecryptionKeyType::SnsKey,
                )
                .await
                .unwrap();
                (session.my_role(), pt)
            }
        };
        let mut dec_results = execute_protocol_small::<_, _, Ring, EXTENSION_DEGREE>(
            N,
            D as u8,
            None,
            NetworkMode::Sync,
            None,
            &mut dec,
            None,
        )
        .await;
        dec_results.sort_by_key(|(r, _)| r.one_based());
        assert_eq!(dec_results.len(), N, "every party must complete the decrypt");
        for (role, pt) in dec_results {
            assert_eq!(
                pt, value,
                "party {role:?} must recover the plaintext via the distributed \
                 degree-aware decrypt"
            );
        }
    }
}
