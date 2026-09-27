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
use algebra::sharing::share::Share;
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

/// Load pk_G from `pk_g.bin`, accepting BOTH on-disk forms:
/// - the simulator's decompressed [`FhePubKeySet`] (`celar-dkg run --write-dev-keys`), and
/// - the ceremony's COMPRESSED `CompressedXofKeySet` (`celar-kms-node` commits the
///   compressed keyset; decompression is a local operation done here).
///
/// A real distributed key comes from `celar-kms-node`, so this MUST handle the
/// compressed form — deserializing it as a `FhePubKeySet` fails with "unexpected
/// end of file". Tries the decompressed form first (cheap), then decompresses.
fn load_pubkeyset(pk_bytes: &[u8]) -> Result<FhePubKeySet> {
    if let Ok(pk) = bincode::deserialize::<FhePubKeySet>(pk_bytes) {
        return Ok(pk);
    }
    let compressed: tfhe::xof_key_set::CompressedXofKeySet = bincode::deserialize(pk_bytes)
        .context("pk_g.bin is neither a FhePubKeySet nor a CompressedXofKeySet")?;
    let (public_key, server_key) = compressed.decompress().into_raw_parts();
    Ok(FhePubKeySet {
        public_key,
        server_key,
    })
}

/// Which session family runs the threshold decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptSession {
    /// Large session, TUniform flooding at `STATSEC_TUNIFORM` (= 52 on the
    /// celar fork, since the derived-bound tightening). THE PRODUCTION PATH —
    /// scales to genesis, backs the §7.2 budget.
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
    session_threshold: Option<usize>,
    out_path: &Path,
) -> Result<DecryptOutput> {
    // Committee shape from the genesis transcript beside the pk. The session
    // threshold the ceremony sharded at is now recorded in the transcript by
    // `collect` (from the fragments), so prefer the explicit flag, else the
    // transcript's recorded t — a ceremony that recorded it needs no flag. Legacy
    // transcripts written before that change carry no recorded t and take the
    // ⌊(c−1)/3⌋ default here, so
    // the flag remains their fallback for a committee keyed below n/3.
    let transcript = Transcript::load(&keys_dir.join("transcript.json"))?;
    let parties = transcript.committee.parties;
    let session_threshold = session_threshold.or(Some(transcript.committee.session_threshold));
    let cfg = CommitteeConfig {
        parties,
        session_threshold,
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
    let pk = load_pubkeyset(&pk_bytes)?;

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

/// Threshold-decrypt against a DEGREE-DECOUPLED key: the shares in `shares_dir`
/// were produced by an upward reshare (`celar-dkg upward-reshare`) to a degree
/// higher than the committee threshold, and reconstruction happens at that
/// degree via [`crate::degree_decrypt::run_degree_aware_decrypt`] rather than
/// the upstream session-degree noiseflood combine.
///
/// Committee size and degree come from the `upward-reshare.json` transcript
/// beside the shares; pk_G is invariant across the reshare and is loaded from
/// the genesis `keys_dir`. Masks are generated locally here (DEV) — a production
/// run sources them from the distributed mask supply. The session's corruption
/// threshold is the Reed-Solomon tolerance ⌊(n−degree−1)/2⌋, decoupled from the
/// key's sharing degree — so this runs the true production shape (e.g. degree 78
/// on 100 seats — illustrative arithmetic, not a size anything has run at) at
/// dev parameters with no committee-size ceiling.
/// Only the production-*parameter* memory/wall confirmation rides a rented
/// large-committee ceremony; the correctness of the topology does not.
pub async fn run_decoupled_threshold_decrypt(
    keys_dir: &Path,
    shares_dir: &Path,
    value: u64,
    out_path: &Path,
) -> Result<DecryptOutput> {
    // Committee shape from the upward-reshare transcript beside the shares.
    let rt = crate::reshare::UpwardReshareTranscript::load(
        &shares_dir.join("upward-reshare.json"),
    )?;
    let parties = rt.new_committee_parties;
    let degree = rt.new_degree;

    // The committee's corruption bound is the Reed-Solomon tolerance the
    // robust-open enforces — floor((n - degree - 1)/2), §7.5 — NOT the degree.
    // This is the decoupling: a degree-`d` key on `n` seats tolerates
    // t = floor((n - d - 1)/2) corruptions, so n >= 3t+1 holds comfortably even
    // when the degree is close to the committee size (d = 78 with n = 100
    // tolerates 10 — arithmetic, not a deployed shape) rather than demanding the
    // impossible n >= 3*degree+1 that a threshold-equals-degree session forces.
    if parties < degree + 1 {
        bail!(
            "committee of {parties} cannot reconstruct a degree-{degree} sharing \
             (need at least degree+1 = {} seats)",
            degree + 1
        );
    }
    let committee_threshold = (parties - degree - 1) / 2;

    // pk_G is invariant across the reshare — from the genesis keys dir.
    let pk_bytes = fs::read(keys_dir.join(PK_FILE))
        .context("reading pk_g.bin (dev keys required)")?;
    let pk = load_pubkeyset(&pk_bytes)?;

    // 1) Encrypt + 2) switch-and-squash — identical to the coupled path.
    tfhe::set_server_key(pk.server_key.clone());
    let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
        .push(value)
        .build();
    let expanded = compact.expand().context("expanding compact list")?;
    let ct: tfhe::FheUint64 = expanded
        .get(0)
        .context("compact list slot 0")?
        .context("slot 0 empty")?;
    let (radix, _, _, _) = ct.into_raw_parts();
    let small_ct = RadixOrBoolCiphertext::Radix(radix);
    let int_server_key: &tfhe::integer::ServerKey = pk.server_key.as_ref();
    let sns_key = pk
        .server_key
        .noise_squashing_key()
        .context("server key has no noise-squashing key")?;
    let large_ct = match &small_ct {
        RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
            sns_key
                .squash_radix_ciphertext_noise(int_server_key, c)
                .map_err(|e| anyhow::anyhow!("switch-and-squash failed: {e:?}"))?,
        ),
        RadixOrBoolCiphertext::Bool(_) => bail!("fixture is a radix ciphertext"),
    };
    let large_ct = Arc::new(large_ct);
    let n_blocks = large_ct.packed_blocks().count();

    // 3) One degree-`degree` flooding mask per block; index each party's shares
    // by one-based role. DEV: generated here; production sources them from the
    // distributed mask supply.
    let mask_batches: Vec<crate::mask_supply::SealedMaskBatch> = (0..n_blocks)
        .map(|_| crate::mask_supply::build_honest_batch(parties, degree, degree + 1))
        .collect::<Result<Vec<_>>>()?;
    let mut mask_by_role: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> =
        vec![Vec::with_capacity(n_blocks); parties];
    for mb in &mask_batches {
        for share in mb.mask_shares() {
            mask_by_role[share.owner().one_based() - 1].push(share.clone());
        }
    }
    let mask_by_role = Arc::new(mask_by_role);

    // 4) Distributed degree-aware decrypt at the KEY's degree.
    let shares_dir_owned = shares_dir.to_path_buf();
    let started = Instant::now();
    let mut task = |session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                    _info: Option<String>| {
        let shares_dir = shares_dir_owned.clone();
        let large_ct = large_ct.clone();
        let mask_by_role = mask_by_role.clone();
        async move {
            let role = session.my_role().one_based();
            let share_bytes = fs::read(shares_dir.join(share_file(role)))
                .expect("reading reshared degree-d share");
            let share: PrivateKeySet<EXTENSION_DEGREE> =
                bincode::deserialize(&share_bytes).expect("deserializing share");
            let pt = crate::degree_decrypt::run_degree_aware_decrypt(
                &session,
                &share,
                &mask_by_role[role - 1],
                &large_ct,
                degree,
                SnsDecryptionKeyType::SnsKey,
            )
            .await
            .expect("degree-aware decrypt failed");
            (role, pt)
        }
    };
    let mut results = execute_protocol_small::<
        _,
        _,
        ResiduePoly<Z128, EXTENSION_DEGREE>,
        EXTENSION_DEGREE,
    >(parties, committee_threshold as u8, None, NetworkMode::Sync, None, &mut task, None)
    .await;
    let wall_secs = started.elapsed().as_secs_f64();

    if results.len() != parties {
        bail!("only {}/{} parties completed decryption", results.len(), parties);
    }
    results.sort_by_key(|(role, _)| *role);
    for (role, recovered) in &results {
        if *recovered != value {
            bail!(
                "party {} recovered {} ≠ expected {} — WRONG PLAINTEXT",
                role,
                recovered,
                value
            );
        }
    }

    let report = DecryptReport {
        schema: DECRYPT_SCHEMA.to_string(),
        mode: format!(
            "DegreeDecoupled (degree {degree} on {parties} seats, committee t={committee_threshold} = RS tolerance ⌊(n−d−1)/2⌋, network open at key degree, DEV masks)"
        ),
        parties,
        value_expected: value,
        recovered: results,
        wall_secs,
        lambda_stat: "46 (decoupled 79-contribution mask ceiling; see budget.rs)",
        flooding_params: "degree-d sealed mask + network robust-open at the key's degree",
    };
    fs::write(out_path, serde_json::to_string_pretty(&report)?)?;
    Ok(DecryptOutput { report })
}

// ---- distributed decoupled decrypt: producer side (single process) --------

/// Shared switch-and-squash ciphertext file — one copy, loaded identically by
/// every seat (the decrypt only agrees if all seats decrypt the SAME ct).
pub const DECOUPLED_CT_FILE: &str = "ct.bin";
/// This seat's flooding-mask shares (one degree-`d` share per block).
pub fn decoupled_mask_file(role: usize) -> String {
    format!("mask_{role:03}.bin")
}
/// Manifest naming the committee shape the seats must all agree on.
pub const DECOUPLED_MANIFEST_FILE: &str = "decrypt-inputs.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoupledDecryptManifest {
    pub schema: String,
    pub value_expected: u64,
    pub parties: usize,
    pub degree: usize,
    /// Session corruption threshold = the RS tolerance ⌊(n−degree−1)/2⌋.
    pub committee_threshold: usize,
    pub n_blocks: usize,
}

pub const DECOUPLED_MANIFEST_SCHEMA: &str = "celar-decoupled-decrypt-inputs/v0";

/// Produce, in one process, the artifacts a DISTRIBUTED decoupled decrypt
/// consumes: the shared SnS ciphertext, per-seat flooding-mask shares, the
/// per-seat degree-`d` key shares (copied from `shares_dir`), pk_G, and a
/// manifest. This is the one-time offline half; the seats then run the
/// networked decrypt over these files (mask sampling is distributed in
/// production — pre-generating here is a measurement/dev convenience and does
/// not change the decrypt's compute or memory footprint).
pub fn prepare_decoupled_decrypt_inputs(
    keys_dir: &Path,
    shares_dir: &Path,
    value: u64,
    signing_keys_dir: Option<&Path>,
    out_dir: &Path,
) -> Result<DecoupledDecryptManifest> {
    let rt = crate::reshare::UpwardReshareTranscript::load(
        &shares_dir.join("upward-reshare.json"),
    )?;
    let parties = rt.new_committee_parties;
    let degree = rt.new_degree;
    if parties < degree + 1 {
        bail!(
            "committee of {parties} cannot reconstruct a degree-{degree} sharing \
             (need at least degree+1 = {} seats)",
            degree + 1
        );
    }
    let committee_threshold = (parties - degree - 1) / 2;
    fs::create_dir_all(out_dir)?;

    // pk_G is invariant across the reshare — from the genesis keys dir.
    let pk_bytes = fs::read(keys_dir.join(PK_FILE))
        .context("reading pk_g.bin (dev keys required)")?;
    let pk = load_pubkeyset(&pk_bytes)?;

    // Encrypt + switch-and-squash — identical to the coupled path.
    tfhe::set_server_key(pk.server_key.clone());
    let compact = tfhe::CompactCiphertextList::builder(&pk.public_key)
        .push(value)
        .build();
    let expanded = compact.expand().context("expanding compact list")?;
    let ct: tfhe::FheUint64 = expanded
        .get(0)
        .context("compact list slot 0")?
        .context("slot 0 empty")?;
    let (radix, _, _, _) = ct.into_raw_parts();
    let small_ct = RadixOrBoolCiphertext::Radix(radix);
    let int_server_key: &tfhe::integer::ServerKey = pk.server_key.as_ref();
    let sns_key = pk
        .server_key
        .noise_squashing_key()
        .context("server key has no noise-squashing key")?;
    let large_ct = match &small_ct {
        RadixOrBoolCiphertext::Radix(c) => SnsRadixOrBoolCiphertext::Radix(
            sns_key
                .squash_radix_ciphertext_noise(int_server_key, c)
                .map_err(|e| anyhow::anyhow!("switch-and-squash failed: {e:?}"))?,
        ),
        RadixOrBoolCiphertext::Bool(_) => bail!("fixture is a radix ciphertext"),
    };
    let n_blocks = large_ct.packed_blocks().count();
    // SnsRadixOrBoolCiphertext itself is not Serialize; its inner tfhe
    // SquashedNoiseRadixCiphertext is. Serialize the inner and reconstruct the
    // wrapper on the seat side.
    let ct_bytes = match &large_ct {
        SnsRadixOrBoolCiphertext::Radix(inner) => {
            bincode::serialize(inner).context("serializing SnS radix ciphertext")?
        }
        SnsRadixOrBoolCiphertext::Bool(_) => bail!("fixture is a radix ciphertext"),
    };
    fs::write(out_dir.join(DECOUPLED_CT_FILE), ct_bytes)?;

    // One degree-`degree` flooding mask per block; split each seat's shares out
    // to its own file, indexed by one-based role. When signing keys are given,
    // each seat's contribution is seeded from H(VRF_sk(epoch‖block) ‖ local_rng)
    // under its own operational key (adopted as a non-optional control by the
    // security review of contribution randomness), so a fleet-wide local-RNG
    // failure stays "predictable to the seat" rather than "to the coalition";
    // without them, a shared local RNG (dev). Reuses the roster-registered
    // ed25519 operational signing key as the VRF key.
    let mask_batches: Vec<crate::mask_supply::SealedMaskBatch> = match signing_keys_dir {
        Some(sk_dir) => {
            use rand::RngCore;
            let epoch = rt.created_unix;
            let mut local = aes_prng::AesRng::from_random_seed();
            (0..n_blocks)
                .map(|block| -> Result<crate::mask_supply::SealedMaskBatch> {
                    let mut seat_seeds: Vec<(usize, [u8; 32])> = Vec::with_capacity(degree + 1);
                    for seat in 1..=(degree + 1) {
                        let key_path = sk_dir.join(format!("signing_party{seat}.key"));
                        let vrf_out =
                            crate::node::vrf_contribution_output(&key_path, epoch, block as u64)?;
                        let mut local_entropy = [0u8; 32];
                        local.fill_bytes(&mut local_entropy);
                        let seed = crate::mask_supply::vrf_mixed_contribution_seed(
                            &vrf_out,
                            &local_entropy,
                        );
                        seat_seeds.push((seat, seed));
                    }
                    crate::mask_supply::build_batch_from_seeds(parties, degree, &seat_seeds)
                })
                .collect::<Result<Vec<_>>>()?
        }
        None => (0..n_blocks)
            .map(|_| crate::mask_supply::build_honest_batch(parties, degree, degree + 1))
            .collect::<Result<Vec<_>>>()?,
    };
    let mut mask_by_role: Vec<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> =
        vec![Vec::with_capacity(n_blocks); parties];
    for mb in &mask_batches {
        for share in mb.mask_shares() {
            mask_by_role[share.owner().one_based() - 1].push(share.clone());
        }
    }
    for (i, shares) in mask_by_role.iter().enumerate() {
        fs::write(
            out_dir.join(decoupled_mask_file(i + 1)),
            bincode::serialize(shares).context("serializing mask shares")?,
        )?;
    }

    // Stage the degree-`d` key shares and pk_G beside the inputs so a seat's
    // input dir is self-contained.
    for role in 1..=parties {
        fs::copy(shares_dir.join(share_file(role)), out_dir.join(share_file(role)))
            .with_context(|| format!("copying degree-d share for role {role}"))?;
    }
    fs::write(out_dir.join(PK_FILE), &pk_bytes)?;

    let manifest = DecoupledDecryptManifest {
        schema: DECOUPLED_MANIFEST_SCHEMA.to_string(),
        value_expected: value,
        parties,
        degree,
        committee_threshold,
        n_blocks,
    };
    fs::write(
        out_dir.join(DECOUPLED_MANIFEST_FILE),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    Ok(manifest)
}
