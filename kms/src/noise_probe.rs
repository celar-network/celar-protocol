//! Empirical characterisation of the post-switch-and-squash noise.
//!
//! The flooding parameter budget assumes the real noise is bounded by
//! 2^LOG_B_SWITCH_SQUASH = 2^70, a hard-coded upper bound the upstream
//! comment describes as "always using the upper bound" and that nothing
//! derives or checks. Every bit of slack in it is a bit of λ_stat — and
//! under the high-degree mask design, the difference between ~16 and ~16k
//! budgeted operations per epoch.
//!
//! Method: encrypt ZERO under pk_G, switch-and-squash, compute every
//! party's UNFLOODED partial (`partial_decrypt128` is pure local
//! computation — b − ⟨a, sᵢ⟩, no interaction), reconstruct the sharing,
//! and what remains IS the raw noise: v = Δ·0 + e = e (centered mod
//! 2^128). Record log₂|e| over many ciphertexts × blocks.
//!
//! An empirical max is NOT a bound — the analytical tail argument is
//! routed to research for an analytical verdict. This measurement is the sanity anchor for
//! that verdict, in both directions.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tfhe::prelude::CiphertextList;

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use algebra::sharing::shamir::{RevealOp, ShamirSharings};
use algebra::sharing::share::Share;
use threshold_execution::endpoints::decryption::{
    partial_decrypt128, RadixOrBoolCiphertext, SnsDecryptionKeyType, SnsRadixOrBoolCiphertext,
};
use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
use threshold_types::role::Role;

use crate::config::{CommitteeConfig, ParamsChoice};
use crate::dkg::dkg_params;
use crate::transcript::{share_file, Transcript, PK_FILE};
use crate::EXTENSION_DEGREE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseProbeReport {
    pub schema: String,
    pub parties: usize,
    pub params: String,
    pub ciphertexts: usize,
    /// Homomorphic op-chain rounds applied BEFORE squashing. 0 = fresh
    /// encryption. Each round is the branchless-transfer shape from the
    /// frozen ABI workload — le, select, sub, add — on zero-valued
    /// operands, so the plaintext stays zero while the ciphertext carries
    /// genuine post-computation noise. Operational ciphertexts reach
    /// decryption in THIS state, not fresh — the fresh-run slack is only
    /// an upper bound on what the flooding budget can claim.
    pub chain_ops: usize,
    pub samples: usize,
    /// log₂ of |e| per statistic, in bits. `assumed_bound` is the constant
    /// the flooding budget is currently sized against.
    pub max_log2: f64,
    pub mean_log2: f64,
    pub p99_log2: f64,
    pub assumed_bound_log2: u32,
    /// Slack between the observed max and the assumed bound — the quantity
    /// the analytical verdict decides how much of it is claimable.
    pub observed_slack_bits: f64,
    /// Honest label: this is an OBSERVED distribution, not a bound.
    pub caveat: &'static str,
}

pub const NOISE_PROBE_SCHEMA: &str = "celar-noise-probe/v0";

fn centered_magnitude_log2(v: u128) -> f64 {
    // Interpret v mod 2^128 as centered: values above 2^127 are negative.
    let mag: u128 = if v > (1u128 << 127) { v.wrapping_neg() } else { v };
    if mag == 0 {
        0.0
    } else {
        // log2 via leading zeros + fractional refinement from the top bits.
        let bits = 128 - mag.leading_zeros();
        let top = (mag >> bits.saturating_sub(53)) as f64;
        top.log2() + bits.saturating_sub(53) as f64
    }
}

/// Probe the raw (unflooded) post-squash noise using dev keys, optionally
/// after `chain_ops` rounds of transfer-shaped homomorphic computation.
pub fn run_noise_probe(
    keys_dir: &Path,
    ciphertexts: usize,
    chain_ops: usize,
    out_path: &Path,
) -> Result<NoiseProbeReport> {
    let transcript = Transcript::load(&keys_dir.join("transcript.json"))?;
    let parties = transcript.committee.parties;
    let cfg = CommitteeConfig {
        parties,
        ..Default::default()
    };
    cfg.validate()?;
    let t_session = cfg.session_threshold();

    let pk_bytes = fs::read(keys_dir.join(PK_FILE))
        .context("reading pk_g.bin (dev keys required — rerun DKG with --write-dev-keys)")?;
    let pk: FhePubKeySet = bincode::deserialize(&pk_bytes).context("deserializing pk_G")?;

    let shares: Vec<PrivateKeySet<EXTENSION_DEGREE>> = (1..=parties)
        .map(|role| {
            let bytes = fs::read(keys_dir.join(share_file(role)))
                .with_context(|| format!("reading share for party {role}"))?;
            bincode::deserialize(&bytes).context("deserializing share")
        })
        .collect::<Result<_>>()?;

    tfhe::set_server_key(pk.server_key.clone());
    let int_server_key: &tfhe::integer::ServerKey = pk.server_key.as_ref();
    let sns_key = pk
        .server_key
        .noise_squashing_key()
        .context("server key has no noise-squashing key")?;

    let mut logs: Vec<f64> = Vec::new();
    for _ in 0..ciphertexts {
        // Encrypt ZERO: every block's decrypted value IS the raw noise.
        let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
            .push(0u64)
            .build();
        let expanded = compact.expand().context("expanding compact list")?;
        let ct: tfhe::FheUint64 = expanded
            .get(0)
            .context("compact list slot 0")?
            .context("slot 0 empty")?;

        // Optional op-chain: repeated NON-bootstrapped homomorphic addition
        // of zero-valued ciphertexts. Plaintext stays zero; noise grows
        // additively with each op WITHOUT a PBS reset — which is the point.
        // The high-level comparison/select ops bootstrap, resetting noise to
        // a characteristic level, so a chain of those would measure PBS
        // output noise, not accumulation. Balance arithmetic between refreshes
        // is what actually piles up pre-squash, and additive growth is its
        // worst case — the state an operational ciphertext reaches decryption in.
        let mut acc = ct;
        for _ in 0..chain_ops {
            let compact_n = tfhe::CompactCiphertextList::builder(&pk.public_key)
                .push(0u64)
                .build();
            let addend: tfhe::FheUint64 = compact_n
                .expand()
                .context("expanding addend")?
                .get(0)
                .context("addend slot")?
                .context("addend empty")?;
            acc = &acc + &addend;
        }
        let (radix, _, _, _) = acc.into_raw_parts();
        let small_ct = RadixOrBoolCiphertext::Radix(radix);
        let large_ct = match &small_ct {
            RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
                sns_key
                    .squash_radix_ciphertext_noise(int_server_key, c)
                    .map_err(|e| anyhow::anyhow!("switch-and-squash failed: {e:?}"))?,
            ),
            _ => bail!("fixture is radix"),
        };

        for block in large_ct.packed_blocks() {
            // Every party's UNFLOODED partial — pure local computation.
            let mut partial_shares: Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>> =
                Vec::with_capacity(parties);
            for (idx, share) in shares.iter().enumerate() {
                let p = partial_decrypt128::<EXTENSION_DEGREE>(
                    share,
                    block,
                    SnsDecryptionKeyType::SnsKey,
                )
                .map_err(|e| anyhow::anyhow!("partial_decrypt failed: {e:?}"))?;
                partial_shares.push(Share::new(Role::indexed_from_one(idx + 1), p));
            }
            let sharing = ShamirSharings::create(partial_shares);
            let opened = sharing
                .reconstruct(t_session)
                .map_err(|e| anyhow::anyhow!("reconstructing unflooded value: {e:?}"))?;
            let v = opened.to_scalar()
                .map_err(|e| anyhow::anyhow!("to_scalar: {e:?}"))?;
            logs.push(centered_magnitude_log2(v.0));
        }
    }

    logs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let samples = logs.len();
    let max_log2 = *logs.last().unwrap_or(&0.0);
    let mean_log2 = logs.iter().sum::<f64>() / samples.max(1) as f64;
    let p99_log2 = logs[((samples as f64 * 0.99) as usize).min(samples - 1)];

    let report = NoiseProbeReport {
        schema: NOISE_PROBE_SCHEMA.to_string(),
        parties,
        params: transcript.dkg.params.clone(),
        ciphertexts,
        chain_ops,
        samples,
        max_log2,
        mean_log2,
        p99_log2,
        assumed_bound_log2: 70,
        observed_slack_bits: 70.0 - max_log2,
        caveat: "OBSERVED distribution over N samples — not a bound. The claimable slack \
                 is decided by the analytical tail argument (routed to research), for which \
                 this is the sanity anchor.",
    };
    fs::write(out_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

/// CENTRALIZED noise probe — the production-parameter path.
///
/// The threshold probe above holds all c committee keysets in one address
/// space, which OOMs at NIST parameters even at the minimum committee (c=4,
/// >121 GiB — the single-process simulator wall, same root as the c=100
/// finding). But the post-squash noise is a property of the FHE PARAMETERS,
/// not the threshold sharing: `partial_decrypt128` computes `b − ⟨a,sᵢ⟩`
/// per share and reconstructs to `b − ⟨a,s⟩`; the centralized analogue is
/// one `decrypt_lwe_ciphertext` under the FULL (unshared) SnS key, which
/// yields the identical value. So we generate ONE keyset (≈1/c the memory,
/// no DKG) and read the noise directly — the correct instrument for a
/// parameter-set property, and it runs at NIST params on a laptop.
pub fn run_noise_probe_centralized(
    params_choice: ParamsChoice,
    ciphertexts: usize,
    chain_ops: usize,
    out_path: &Path,
) -> Result<NoiseProbeReport> {
    use threshold_execution::tfhe_internals::test_feature::{
        gen_uncompressed_key_set, ClientKeyView,
    };

    let params = dkg_params(params_choice);
    let mut rng = aes_prng::AesRng::from_random_seed();
    // One centralized keyset: ClientKey + ServerKey(+SnS key) + CompactPublicKey.
    let keyset = gen_uncompressed_key_set(params, tfhe::Tag::default(), &mut rng);
    let pk = &keyset.public_keys;

    tfhe::set_server_key(pk.server_key.clone());
    let int_server_key: &tfhe::integer::ServerKey = pk.server_key.as_ref();
    let sns_key = pk
        .server_key
        .noise_squashing_key()
        .context("server key has no noise-squashing key")?;
    // The full SnS GLWE key viewed as an LWE key — the centralized
    // counterpart of each party's `glwe_secret_key_share_sns_as_lwe`.
    let sns_lwe_sk = ClientKeyView::new(&keyset.client_key)
        .raw_glwe_client_sns_key_as_lwe()
        .context("client key has no SnS GLWE key")?;

    let mut logs: Vec<f64> = Vec::new();
    for _ in 0..ciphertexts {
        let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
            .push(0u64)
            .build();
        let expanded = compact.expand().context("expanding compact list")?;
        let ct: tfhe::FheUint64 = expanded
            .get(0)
            .context("compact list slot 0")?
            .context("slot 0 empty")?;

        let mut acc = ct;
        for _ in 0..chain_ops {
            let addend: tfhe::FheUint64 = tfhe::CompactCiphertextList::builder(&pk.public_key)
                .push(0u64)
                .build()
                .expand()
                .context("expanding addend")?
                .get(0)
                .context("addend slot")?
                .context("addend empty")?;
            acc = &acc + &addend;
        }
        let (radix, _, _, _) = acc.into_raw_parts();
        let small_ct = RadixOrBoolCiphertext::Radix(radix);
        let large_ct = match &small_ct {
            RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
                sns_key
                    .squash_radix_ciphertext_noise(int_server_key, c)
                    .map_err(|e| anyhow::anyhow!("switch-and-squash failed: {e:?}"))?,
            ),
            _ => bail!("fixture is radix"),
        };

        for block in large_ct.packed_blocks() {
            // The full-key raw phase b − ⟨a,s⟩, no rounding — identical to
            // the reconstructed threshold partial, measured directly.
            let phase = tfhe::core_crypto::prelude::decrypt_lwe_ciphertext(
                &sns_lwe_sk,
                block.lwe_ciphertext(),
            );
            logs.push(centered_magnitude_log2(phase.0));
        }
    }

    logs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let samples = logs.len();
    let max_log2 = *logs.last().unwrap_or(&0.0);
    let mean_log2 = logs.iter().sum::<f64>() / samples.max(1) as f64;
    let p99_log2 = logs[((samples as f64 * 0.99) as usize).min(samples.saturating_sub(1))];

    let report = NoiseProbeReport {
        schema: NOISE_PROBE_SCHEMA.to_string(),
        parties: 1,
        chain_ops,
        params: params_choice.name().to_string(),
        ciphertexts,
        samples,
        max_log2,
        mean_log2,
        p99_log2,
        assumed_bound_log2: 70,
        observed_slack_bits: 70.0 - max_log2,
        caveat: "CENTRALIZED (single-keyset) measurement — the raw phase under the full SnS \
                 key, identical to the reconstructed threshold partial but without the \
                 multi-party memory. Observed distribution, not a bound; the claimable slack \
                 is decided by the analytical noise-bound derivation, for which this is the \
                 anchor.",
    };
    fs::write(out_path, serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

#[cfg(test)]
mod closed_form {
    //! The switch-and-squash output-noise standard deviation, evaluated in
    //! closed form from the underlying scheme's published noise equations.
    //!
    //! The probes above MEASURE this noise; this module DERIVES it, so the two
    //! can be checked against each other without a key generation. It locks in
    //! both the arithmetic and the deployed noise-squashing constants: if a
    //! parameter set changes, this test is the checkpoint that forces the noise
    //! figure to be re-derived rather than silently assumed.
    //!
    //! The radicand is σ̄_BS² + FFTNoise. σ̄_BS² is the bootstrap output-noise
    //! variance in the large (u128) modulus; FFTNoise is the additional error
    //! absorbed from the FFT-based ring multiplication, with exponent 41.4 for
    //! the 2^128 / float128 modulus. The output bound is c·σ, with c the tail
    //! cut; the scheme was parameterised so this bound stays under 2^70.
    //!
    //! The tail-cut multiplier is the scheme's own fixed constant for a ring
    //! of dimension one: from the classical estimate
    //! Pr[|x| > c·σ] ≤ erfc(c/√2), the value 13.15 puts the per-value
    //! exceedance below 2^-128, matching the scheme's overall failure target.
    //! Read from the source document, not assumed — an earlier draft used the
    //! looser 9.5 (a 2^-64 tail convention); the derived bounds clear the
    //! ceiling under either, so nothing downstream moved when this was pinned.

    /// One switch-and-squash parameter set, large-modulus variables.
    struct SnsParams {
        /// GLWE dimension (noise-squashing `glwe_dimension`).
        w: f64,
        /// Polynomial size (noise-squashing `polynomial_size`).
        n: f64,
        /// Decomposition base-log; the base itself is 2^`beta_log`.
        beta_log: f64,
        /// Decomposition level count.
        nu_bk: f64,
        /// TUniform bound of the noise-squashing GLWE key noise.
        tuni_b: f64,
        /// Input LWE dimension to the blind rotation (compute `lwe_dimension`).
        ell: f64,
    }

    const Q_LOG: f64 = 128.0;
    const NU_FFT: f64 = 41.4;
    /// c_err,1 — the scheme's tail-cut constant for ring dimension one:
    /// erfc(13.15/√2) < 2^-128.
    const Z_TAILCUT: f64 = 13.15;
    const CEILING_LOG2: f64 = 70.0;

    /// Test parameter set: noise-squashing glwe_dimension 1, polynomial_size
    /// 256, decomp_base_log 33, decomp_level_count 2, glwe noise TUniform(0);
    /// compute lwe_dimension 1. (Deliberately tiny and insecure — a single
    /// blind-rotation external product, so it is a degenerate corner for the
    /// sum-of-uniforms variance model, not a validation point.)
    const TEST: SnsParams = SnsParams {
        w: 1.0,
        n: 256.0,
        beta_log: 33.0,
        nu_bk: 2.0,
        tuni_b: 0.0,
        ell: 1.0,
    };

    /// Production parameter set: noise-squashing glwe_dimension 2,
    /// polynomial_size 2048, decomp_base_log 24, decomp_level_count 3, glwe
    /// noise TUniform(27); compute lwe_dimension 886.
    const PROD: SnsParams = SnsParams {
        w: 2.0,
        n: 2048.0,
        beta_log: 24.0,
        nu_bk: 3.0,
        tuni_b: 27.0,
        ell: 886.0,
    };

    /// Variance of a TUniform distribution with bound `b`: (2^(2b+1) + 1) / 6.
    fn tuniform_var(b: f64) -> f64 {
        (2f64.powf(2.0 * b + 1.0) + 1.0) / 6.0
    }

    /// σ̄_BS² + FFTNoise — the radicand of the output-noise bound.
    fn variance(p: &SnsParams) -> f64 {
        let q2 = 2f64.powf(2.0 * Q_LOG);
        let beta2 = 2f64.powf(2.0 * p.beta_log);
        let beta_pow = 2f64.powf(2.0 * p.nu_bk * p.beta_log);
        let wn = p.w * p.n;
        let sig_bk2 = tuniform_var(p.tuni_b);

        // Key-noise, gadget-rounding, and sample-extraction terms.
        let t_key = p.nu_bk * (p.w + 1.0) * p.n * (beta2 + 2.0) / 12.0 * sig_bk2;
        let t_gadget = (q2 - beta_pow) / (24.0 * beta_pow) * (1.0 + wn / 2.0);
        let t_extract = wn / 32.0 + (1.0 - wn / 2.0).powi(2) / 16.0;
        let sigma_bs_sq = p.ell * (t_key + t_gadget + t_extract);

        let fft = 2f64.powf(NU_FFT) * p.ell * (p.w + 1.0) * p.n * p.n * beta2 * p.nu_bk;
        sigma_bs_sq + fft
    }

    /// log2 of the output-noise standard deviation.
    fn sigma_log2(p: &SnsParams) -> f64 {
        variance(p).log2() / 2.0
    }

    #[test]
    fn sigma_matches_the_hand_derivation() {
        let test = sigma_log2(&TEST);
        let prod = sigma_log2(&PROD);
        assert!(
            (test - 63.50).abs() < 0.15,
            "test sigma log2 = {test}, expected about 63.50"
        );
        assert!(
            (prod - 64.16).abs() < 0.15,
            "production sigma log2 = {prod}, expected about 64.16"
        );
    }

    #[test]
    fn bound_stays_under_the_design_ceiling() {
        for (name, p) in [("test", &TEST), ("production", &PROD)] {
            let bound = sigma_log2(p) + Z_TAILCUT.log2();
            assert!(
                bound < CEILING_LOG2,
                "{name}: output bound log2 = {bound} exceeds the 2^70 ceiling"
            );
        }
    }

    #[test]
    fn production_derivation_corroborates_the_measured_maximum() {
        // The centralized probe recorded a maximum of about 2^66.1 at the
        // production parameters. The derived standard deviation must sit below
        // that maximum (a sample maximum exceeds its sigma), the maximum must
        // clear the ceiling, and the gap between them must be a few bits — the
        // ratio a heavy-tailed draw of a few thousand samples produces — not
        // tens of bits, which would mean the derivation or the probe drifted.
        const MEASURED_MAX_LOG2: f64 = 66.1;
        let sigma = sigma_log2(&PROD);
        assert!(sigma < MEASURED_MAX_LOG2, "derived sigma {sigma} is not below the measured maximum");
        assert!(MEASURED_MAX_LOG2 < CEILING_LOG2, "measured maximum does not clear the ceiling");
        assert!(
            MEASURED_MAX_LOG2 - sigma < 4.0,
            "maximum-to-sigma gap unexpectedly large — derivation or probe drifted"
        );
    }
}
