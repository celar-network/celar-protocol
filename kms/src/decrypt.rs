//! Threshold decryption with noise flooding (§7.2) — the reveal path.
//!
//! Flow (upstream NoiseFloodSmall mode, the §7.2 flooding default):
//! 1. encrypt the fixture value under pk_G (compact public key from the DKG);
//! 2. **switch-and-squash** the ciphertext to the large parameter set with
//!    the server key's noise-squashing key (done once, public material only);
//! 3. each party: Z128 small session → noise-flood preprocessing → partial
//!    decryption with flooding noise → robust combine → plaintext.
//!
//! The inner decryption path is SWAPPABLE by construction (onboarding design
//! constraint): upstream ships both `SecureOnlineNoiseFloodDecryption`
//! (flooding, wired here) and a bitdec path (the MPC-rounding alternative) —
//! switching means one type parameter, not a rewrite.
//!
//! Honest labels: λ_stat and the flooding parameters are those of the
//! upstream parameter set and are UNCHARACTERISED by us (recorded in the
//! report, not asserted). `--shares-dir` decouples shares from pk so a later
//! milestone can prove resharing's "old shares dead" claim functionally.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
// tfhe 1.7: `get` on an expanded compact list comes from this trait.
use tfhe::prelude::CiphertextList;

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
// (0.13.22 → main: `decryption_non_wasm` is now a PRIVATE module, re-exported
// wholesale by `endpoints::decryption` — upstream lib.rs says so explicitly.
// Both groups therefore come from `decryption`.)
use threshold_execution::endpoints::decryption::{
    run_decryption_noiseflood_64, OfflineNoiseFloodSession, RadixOrBoolCiphertext,
    SecureNoiseFloodLargeSession, SecureOnlineNoiseFloodDecryption,
    SmallOfflineNoiseFloodSession, SnsDecryptionKeyType, SnsRadixOrBoolCiphertext,
};
use threshold_execution::runtime::sessions::base_session::GenericBaseSessionHandles;
use threshold_execution::runtime::sessions::large_session::LargeSession;
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
use threshold_execution::runtime::sessions::small_session::SmallSession;
use threshold_execution::tests::helper::tests_and_benches::{
    execute_protocol_large, execute_protocol_small,
};
use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
use threshold_types::network::NetworkMode;

use crate::config::CommitteeConfig;
use crate::transcript::{share_file, Transcript, PK_FILE};
use crate::EXTENSION_DEGREE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptReport {
    pub schema: String,
    /// Upstream decryption mode used.
    pub mode: String,
    pub parties: usize,
    pub value_expected: u64,
    /// Per-role recovered plaintexts (must all agree).
    pub recovered: Vec<(usize, u64)>,
    pub wall_secs: f64,
    /// Honest labels — these are the upstream parameter set's properties,
    /// not characterised by us. Asserting them here would repeat the
    /// bake-off mistake.
    pub lambda_stat: &'static str,
    pub flooding_params: &'static str,
}

pub const DECRYPT_SCHEMA: &str = "celar-decrypt-report/v0";

/// The flooding parameter of the PRODUCTION decrypt path, declared HERE —
/// next to the code that runs it — and consumed by `budget.rs`'s mirror
/// test. The budget's λ_stat must equal what the deployed decrypt path
/// actually floods with; anchoring the number in this module (rather than
/// to the library constant in the abstract) means a future path change
/// breaks the mirror test instead of silently un-backing the budget.
///
/// Production = the LARGE-session TUniform path: it is the only path that
/// reaches genesis scale (the PRSS path is hard-capped at binom(n,t) ≤ 2047)
/// AND the only one whose ceiling admits 50 (no binom factor in its mask).
pub const PRODUCTION_FLOODING_STATSEC: u32 = threshold_execution::constants::STATSEC_TUNIFORM;

/// Which session family runs the threshold decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptSession {
    /// Large session, TUniform flooding at `STATSEC_TUNIFORM` (= 50 on the
    /// celar fork). THE PRODUCTION PATH — scales to genesis, backs the
    /// §7.2 budget.
    Large,
    /// Small session, PRSS flooding at `STATSEC` (= 40). Dev/comparison
    /// only: hard-capped at small committees and does NOT back the budget.
    SmallDev,
}

impl DecryptSession {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "large" => Ok(Self::Large),
            "small" => Ok(Self::SmallDev),
            other => bail!("unknown --session {other:?} (expected large | small)"),
        }
    }
}

pub struct DecryptOutput {
    pub report: DecryptReport,
}

/// Threshold-decrypt a fixture value: encrypt under `keys_dir`'s pk_G, then
/// n parties (shares from `shares_dir`, default = keys_dir) run the
/// noise-flooded protocol. Every party must recover `value`.
pub async fn run_local_threshold_decrypt(
    keys_dir: &Path,
    shares_dir: &Path,
    value: u64,
    session_kind: DecryptSession,
    out_path: &Path,
) -> Result<DecryptOutput> {
    // Committee shape from the genesis transcript beside the pk.
    let transcript = Transcript::load(&keys_dir.join("transcript.json"))?;
    let parties = transcript.committee.parties;
    let cfg = CommitteeConfig {
        parties,
        ..Default::default()
    };
    cfg.validate()?;
    // The large path's noiseflood preprocessing is SecureLargePreprocessing,
    // which robust-opens degree-2t values — the same n ≥ 4t+1 safety
    // interlock as the DKG's secure-large mode, refused here at entry
    // rather than five layers down. c=4 fixtures need --session small (dev)
    // or c ≥ 5 keys.
    if session_kind == DecryptSession::Large && parties <= 4 * cfg.session_threshold() {
        bail!(
            "--session large requires parties ≥ 4·t_session + 1 (got c={}, t={}): \
             the TUniform offline phase robust-opens degree-2t values. Re-key with \
             c ≥ {} or use --session small (dev only — floods at 40, does NOT back \
             the §7.2 budget).",
            parties,
            cfg.session_threshold(),
            4 * cfg.session_threshold() + 1
        );
    }

    // pk_G: FhePubKeySet { public_key (compact), server_key } from the DKG.
    let pk_bytes = fs::read(keys_dir.join(PK_FILE))
        .context("reading pk_g.bin (dev keys required — rerun DKG with --write-dev-keys)")?;
    let pk: FhePubKeySet = bincode::deserialize(&pk_bytes).context("deserializing pk_G")?;

    // 1) Encrypt the fixture value under pk_G, exactly as a client would.
    tfhe::set_server_key(pk.server_key.clone());
    let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
        .push(value)
        .build();
    let expanded = compact.expand().context("expanding compact list")?;
    let ct: tfhe::FheUint64 = expanded
        .get(0)
        .context("compact list slot 0")?
        .context("slot 0 empty")?;
    // (tfhe 1.6 → 1.7: into_raw_parts gained a 4th member,
    // ReRandomizationMetadata — dropped here; this decrypt path never
    // re-randomizes. NOTE for G6 and the op set: upstream now carries re-randomization
    // metadata ON the ciphertext, which the op-stream's §7 deterministic
    // re-randomization design should be checked against.)
    let (radix, _, _, _) = ct.into_raw_parts();
    let small_ct = RadixOrBoolCiphertext::Radix(radix);

    // 2) Switch-and-squash once — public material only (server key).
    // (tfhe 1.6 → 1.7: one fewer deref — `as_ref()` already lands on
    // integer::ServerKey.)
    let int_server_key: &tfhe::integer::ServerKey = pk.server_key.as_ref();
    let sns_key = pk
        .server_key
        .noise_squashing_key()
        .context("server key has no noise-squashing key — DKG params must be WithSnS")?;
    let large_ct = match &small_ct {
        RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
            sns_key
                .squash_radix_ciphertext_noise(int_server_key, c)
                .map_err(|e| anyhow::anyhow!("switch-and-squash failed: {e:?}"))?,
        ),
        RadixOrBoolCiphertext::Bool(_) => bail!("fixture is a radix ciphertext"),
    };
    let large_ct = Arc::new(large_ct);
    let num_blocks = small_ct.len();

    // 3) n-party noise-flooded threshold decryption, on the selected path.
    let shares_dir_owned = shares_dir.to_path_buf();
    let started = Instant::now();

    let mut results = match session_kind {
        DecryptSession::SmallDev => {
            let mut task = |session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                            _info: Option<String>| {
                let shares_dir = shares_dir_owned.clone();
                let large_ct = large_ct.clone();
                async move {
                    let role = session.my_role().one_based();
                    let share_bytes = fs::read(shares_dir.join(share_file(role)))
                        .expect("reading share file (dev keys required)");
                    let share: PrivateKeySet<EXTENSION_DEGREE> =
                        bincode::deserialize(&share_bytes).expect("deserializing share");

                    let mut nf_session = SmallOfflineNoiseFloodSession::new(session);
                    let preproc = nf_session
                        .init_prep_noiseflooding(num_blocks)
                        .await
                        .expect("noise-flood preprocessing failed");

                    let out = run_decryption_noiseflood_64::<
                        EXTENSION_DEGREE,
                        _,
                        _,
                        SecureOnlineNoiseFloodDecryption,
                    >(
                        nf_session.session.get_mut(),
                        Arc::new(Mutex::new(preproc)),
                        Arc::new(share),
                        large_ct,
                        SnsDecryptionKeyType::SnsKey,
                    )
                    .await
                    .expect("threshold decryption failed");

                    (role, out.0)
                }
            };
            execute_protocol_small::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                cfg.parties,
                cfg.session_threshold() as u8,
                None,
                NetworkMode::Sync,
                None,
                &mut task,
                None,
            )
            .await
        }
        DecryptSession::Large => {
            // The production path: large session, real TUniform flooding at
            // STATSEC_TUNIFORM via SecureLargePreprocessing. Sync mode + the
            // widened round timeout, same reasons as the DKG's secure-large
            // path (heavy offline compute between sync rounds; a dev run
            // time-slices all c parties on one machine).
            let mut task = |mut session: LargeSession| {
                let shares_dir = shares_dir_owned.clone();
                let large_ct = large_ct.clone();
                async move {
                    let role = session.my_role().one_based();
                    let share_bytes = fs::read(shares_dir.join(share_file(role)))
                        .expect("reading share file (dev keys required)");
                    let share: PrivateKeySet<EXTENSION_DEGREE> =
                        bincode::deserialize(&share_bytes).expect("deserializing share");

                    session
                        .network()
                        .set_timeout_for_next_round(std::time::Duration::from_secs(600))
                        .await;

                    let mut nf_session = SecureNoiseFloodLargeSession::new(session);
                    let preproc = nf_session
                        .init_prep_noiseflooding(num_blocks)
                        .await
                        .expect("noise-flood preprocessing failed (large/TUniform path)");

                    let out = run_decryption_noiseflood_64::<
                        EXTENSION_DEGREE,
                        _,
                        _,
                        SecureOnlineNoiseFloodDecryption,
                    >(
                        nf_session.session.get_mut(),
                        Arc::new(Mutex::new(preproc)),
                        Arc::new(share),
                        large_ct,
                        SnsDecryptionKeyType::SnsKey,
                    )
                    .await
                    .expect("threshold decryption failed");

                    (role, out.0)
                }
            };
            execute_protocol_large::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
                cfg.parties,
                cfg.session_threshold(),
                None,
                NetworkMode::Sync,
                None,
                &mut task,
            )
            .await
        }
    };
    let wall_secs = started.elapsed().as_secs_f64();

    if results.len() != parties {
        bail!("only {}/{} parties completed decryption", results.len(), parties);
    }
    results.sort_by_key(|(role, _)| *role);

    // Every party must independently recover the fixture value.
    for (role, recovered) in &results {
        if *recovered != value {
            bail!(
                "party {} recovered {} ≠ expected {} — WRONG PLAINTEXT (mixed-epoch \
                 shares? corrupted share files?)",
                role,
                recovered,
                value
            );
        }
    }

    let (mode, lambda_stat, flooding_params) = match session_kind {
        DecryptSession::Large => (
            "NoiseFloodLarge (TUniform, production)".to_string(),
            // Characterised at last — by the flooding-margin analysis, not by
            // assumption: ceiling 50 with 2x headroom on this path
            // (see the margin note), deployed via the celar fork.
            "50 (STATSEC_TUNIFORM, celar fork; ceiling analysis in the margin note)",
            "TUniform(120) x2 summed; mask < 2^121, margin 2^122",
        ),
        DecryptSession::SmallDev => (
            "NoiseFloodSmall (PRSS, DEV — does not back the budget)".to_string(),
            "40 (PRSS path ceiling at PRSS_SIZE_MAX; dev/comparison only)",
            "PRSS mask, binom(n,t) factor; at its ceiling by design",
        ),
    };
    let report = DecryptReport {
        schema: DECRYPT_SCHEMA.to_string(),
        mode,
        parties,
        value_expected: value,
        recovered: results,
        wall_secs,
        lambda_stat,
        flooding_params,
    };
    fs::write(out_path, serde_json::to_string_pretty(&report)?)?;
    Ok(DecryptOutput { report })
}
