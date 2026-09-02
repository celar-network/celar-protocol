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

use crate::config::CommitteeConfig;
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
