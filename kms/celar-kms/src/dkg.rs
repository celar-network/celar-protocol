//! B1: local n-party DKG over `threshold-execution`, producing the
//! transcript artifact.
//!
//! Two offline phases (config `preprocessing`):
//! - **dummy** — `DummyPreprocessing`, seconds, NOT cryptographic. Dev only.
//! - **secure** — `SecureSmallPreprocessing`: the real MPC offline phase
//!   (triples + randomness over sync reliable broadcast), then a DKG
//!   preprocessing store filled from it. This is what a genesis ceremony
//!   runs; expect a long wall-clock at real parameter sets.
//!
//! Remaining swap points, in order of arrival:
//! - networking: local test runtime → gRPC/mTLS ceremony node (S2), one
//!   process per committee member (H2);
//! - parameters: test set → the audited Celar 𝒫_FHE choice.
//! The transcript format is invariant across those swaps by design.

use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use threshold_execution::config::BatchParams;
use threshold_execution::endpoints::keygen::{
    OnlineDistributedKeyGen, SecureOnlineDistributedKeyGen128,
};
use threshold_execution::keyset_config::KeySetConfig;
use threshold_execution::online::preprocessing::dummy::DummyPreprocessing;
use threshold_execution::online::preprocessing::{create_memory_factory, DKGPreprocessing};
use threshold_execution::runtime::sessions::base_session::{
    GenericBaseSessionHandles, ToBaseSession,
};
use threshold_execution::runtime::sessions::large_session::LargeSession;
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
use threshold_execution::runtime::sessions::small_session::SmallSession;
use threshold_execution::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
use threshold_execution::tests::helper::tests_and_benches::{
    execute_protocol_large, execute_protocol_small,
};
use threshold_execution::tfhe_internals::parameters::{
    DKGParams, DKGParamsBasics, NIST_PARAMS_P32_SNS_FGLWE, PARAMS_TEST_BK_SNS,
};
use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
use threshold_types::network::NetworkMode;

use crate::config::{CommitteeConfig, ParamsChoice, PreprocMode};
use crate::transcript::{share_file, sha256_hex, PartyRecord, Transcript, PK_FILE};
use crate::EXTENSION_DEGREE;

/// The upstream local harness fixes the session id.
const LOCAL_SESSION_ID: u64 = 1;

type PartyResult = (usize, FhePubKeySet, PrivateKeySet<EXTENSION_DEGREE>);

fn dkg_params(choice: ParamsChoice) -> DKGParams {
    match choice {
        ParamsChoice::Test => PARAMS_TEST_BK_SNS,
        ParamsChoice::NistP32SnsFglwe => NIST_PARAMS_P32_SNS_FGLWE,
    }
}

fn build_tag(bytes: &[u8]) -> tfhe::Tag {
    let mut tag = tfhe::Tag::default();
    tag.set_data(bytes);
    tag
}

/// Outcome of a local DKG run.
pub struct DkgRunOutput {
    pub transcript: Transcript,
}

/// Dummy offline phase: one large session per party, async network mode
/// (fine because the preprocessing is not interactive). Mirrors upstream's
/// own DKG integration tests.
async fn run_parties_dummy(cfg: &CommitteeConfig) -> Vec<PartyResult> {
    let params = dkg_params(cfg.params);
    let seed = cfg.preproc_seed;
    let tag_bytes = cfg.tag.clone().into_bytes();

    let mut task = |mut session: LargeSession| {
        let tag_bytes = tag_bytes.clone();
        async move {
            let role = session.my_role().one_based();
            let mut preproc = DummyPreprocessing::new(seed, &session);
            let (pk, sk) = SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::keygen(
                &mut session,
                &mut preproc,
                params,
                build_tag(&tag_bytes),
            )
            .await
            .expect("distributed keygen failed");
            (role, pk, sk)
        }
    };

    execute_protocol_large::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
        cfg.parties,
        cfg.session_threshold(),
        None,
        NetworkMode::Async,
        None,
        &mut task,
    )
    .await
}

/// Secure offline phase (H1): one small session (PRSS-initialised) per
/// party, SYNC network mode (the reliable-broadcast offline protocol assumes
/// synchrony), real triple/randomness generation sized from the parameter
/// set, then keygen over the filled DKG preprocessing store.
async fn run_parties_secure(cfg: &CommitteeConfig) -> Vec<PartyResult> {
    let params = dkg_params(cfg.params);
    let keyset_config = KeySetConfig::default();
    let params_handle = params.get_params_basics_handle();
    let batch = BatchParams {
        triples: params_handle.total_triples_required(keyset_config),
        randoms: params_handle.total_randomness_required(keyset_config),
    };
    let tag_bytes = cfg.tag.clone().into_bytes();

    let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                    _info: Option<String>| {
        let tag_bytes = tag_bytes.clone();
        async move {
            let role = session.my_role().one_based();

            // 0) widen the per-round network timeout. The Sync-mode local
            // runtime drops shares of parties that miss a round deadline, and
            // the secure offline/fill phases have heavy compute between
            // rounds — without this, robust open fails with "Could not
            // reconstruct the sharing" (all parties late, 0/c complete).
            // Upstream's secure-preproc tests set 240s; we use 600s because a
            // dev run time-slices all c parties on one machine.
            session
                .network()
                .set_timeout_for_next_round(std::time::Duration::from_secs(600))
                .await;

            // 1) the real offline phase — this is the expensive part.
            let mut small_preproc = SecureSmallPreprocessing::default()
                .execute(&mut session, batch)
                .await
                .expect("secure offline phase failed");

            // 2) shape it into DKG preprocessing material.
            let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();
            dkg_preproc
                .fill_from_base_preproc(
                    params,
                    keyset_config,
                    session.get_mut_base_session(),
                    &mut small_preproc,
                )
                .await
                .expect("filling DKG preprocessing failed");

            // 3) the online keygen, identical to the dummy path.
            let (pk, sk) = SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::keygen(
                session.get_mut_base_session(),
                dkg_preproc.as_mut(),
                params,
                build_tag(&tag_bytes),
            )
            .await
            .expect("distributed keygen failed");
            (role, pk, sk)
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

/// Run the genesis-mode DKG locally with `cfg.parties` members and write the
/// transcript (plus, optionally, dev key material for level-2 verification)
/// into `out_dir`.
///
/// `write_dev_keys` writes pk_G and the per-party share vectors as bincode
/// blobs. Shares on disk are a DEV-ONLY convenience for re-verifiability —
/// a real ceremony never persists a share unprotected.
pub async fn run_local_dkg(
    cfg: &CommitteeConfig,
    out_dir: &Path,
    write_dev_keys: bool,
) -> Result<DkgRunOutput> {
    cfg.validate()?;
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;

    let started = Instant::now();
    let mut results = match cfg.preprocessing {
        PreprocMode::Dummy => run_parties_dummy(cfg).await,
        PreprocMode::Secure => run_parties_secure(cfg).await,
    };
    let wall_secs = started.elapsed().as_secs_f64();

    if results.len() != cfg.parties {
        bail!(
            "only {}/{} parties completed the protocol — see logs",
            results.len(),
            cfg.parties
        );
    }
    results.sort_by_key(|(role, _, _)| *role);

    // pk_G must be identical across parties — that IS the "same group key"
    // property. Serialize each party's view, compare digests, keep one.
    let mut pk_digest: Option<String> = None;
    let mut pk_bytes_keep: Option<Vec<u8>> = None;
    let mut party_records = Vec::with_capacity(results.len());

    for (role, pk, sk) in &results {
        let pk_bytes = bincode::serialize(pk).context("serializing pk_G")?;
        let digest = sha256_hex(&pk_bytes);
        match &pk_digest {
            None => {
                pk_digest = Some(digest);
                pk_bytes_keep = Some(pk_bytes);
            }
            Some(first) if *first != digest => {
                bail!(
                    "party {} derived a DIFFERENT pk_G ({} vs {}) — protocol violation",
                    role,
                    digest,
                    first
                );
            }
            _ => {}
        }

        let sk_bytes = bincode::serialize(sk).context("serializing share vector")?;
        party_records.push(PartyRecord {
            role: *role,
            share_commitment_sha256: sha256_hex(&sk_bytes),
        });

        if write_dev_keys {
            fs::write(out_dir.join(share_file(*role)), &sk_bytes)
                .with_context(|| format!("writing share file for party {role}"))?;
        }
    }

    let pk_digest = pk_digest.expect("at least one party");
    if write_dev_keys {
        fs::write(
            out_dir.join(PK_FILE),
            pk_bytes_keep.expect("pk bytes kept"),
        )
        .context("writing pk_G file")?;
        fs::write(
            out_dir.join("DEV-KEYS-WARNING.txt"),
            "Key material written by a DEV run of celar-dkg for transcript\n\
             re-verification. A real ceremony never persists shares unprotected.\n",
        )?;
    }

    let transcript = Transcript::build(
        cfg,
        LOCAL_SESSION_ID,
        pk_digest,
        party_records,
        Some(wall_secs),
    );
    transcript.save(&out_dir.join("transcript.json"))?;
    transcript.verify_internal()?; // never publish an artifact we can't verify

    Ok(DkgRunOutput { transcript })
}
