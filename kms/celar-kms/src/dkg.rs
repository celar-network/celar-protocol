//! B1 skeleton: local n-party DKG over `threshold-execution`, producing the
//! transcript artifact.
//!
//! The run uses the upstream local test runtime (`testing` feature): every
//! committee member is a tokio task wired over in-memory networking, exactly
//! the shape of upstream's own DKG integration tests. Swap points, in order
//! of arrival:
//! - preprocessing: `DummyPreprocessing` → the real offline factory
//!   (`SecureSmallPreprocessing` / orchestrated);
//! - networking: local runtime → gRPC/mTLS (S2), one process per member;
//! - parameters: test set → the audited Celar 𝒫_FHE choice.
//! The transcript format is invariant across those swaps by design.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use threshold_execution::endpoints::keygen::{
    OnlineDistributedKeyGen, SecureOnlineDistributedKeyGen128,
};
use threshold_execution::online::preprocessing::dummy::DummyPreprocessing;
use threshold_execution::runtime::sessions::large_session::LargeSession;
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
use threshold_execution::tests::helper::tests_and_benches::execute_protocol_large;
use threshold_execution::tfhe_internals::parameters::{
    DKGParams, NIST_PARAMS_P32_SNS_FGLWE, PARAMS_TEST_BK_SNS,
};
use threshold_types::network::NetworkMode;

use crate::config::{CommitteeConfig, ParamsChoice};
use crate::transcript::{share_file, sha256_hex, PartyRecord, Transcript, PK_FILE};
use crate::EXTENSION_DEGREE;

/// The upstream local harness fixes the session id.
const LOCAL_SESSION_ID: u64 = 1;

fn dkg_params(choice: ParamsChoice) -> DKGParams {
    match choice {
        ParamsChoice::Test => PARAMS_TEST_BK_SNS,
        ParamsChoice::NistP32SnsFglwe => NIST_PARAMS_P32_SNS_FGLWE,
    }
}

/// Outcome of a local DKG run, before/after transcript construction.
pub struct DkgRunOutput {
    pub transcript: Transcript,
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

    let params = dkg_params(cfg.params);
    let seed = cfg.preproc_seed;
    let tag_bytes = cfg.tag.clone().into_bytes();

    // One async task per committee member; each runs the full keygen protocol
    // against its session handle. Mirrors upstream's run_dkg_and_save.
    let mut task = |mut session: LargeSession| {
        let tag_bytes = tag_bytes.clone();
        async move {
            let role = session.my_role().one_based();
            let mut preproc = DummyPreprocessing::new(seed, &session);
            let mut tag = tfhe::Tag::default();
            tag.set_data(&tag_bytes);
            let (pk, sk) = SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::keygen(
                &mut session,
                &mut preproc,
                params,
                tag,
            )
            .await
            .expect("distributed keygen failed");
            (role, pk, sk)
        }
    };

    // Async network mode: fine while preprocessing is dummy (upstream note).
    let mut results = execute_protocol_large::<
        _,
        _,
        ResiduePoly<Z128, EXTENSION_DEGREE>,
        EXTENSION_DEGREE,
    >(
        cfg.parties,
        cfg.session_threshold(),
        None,
        NetworkMode::Async,
        None,
        &mut task,
    )
    .await;

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

    let transcript = Transcript::build(cfg, LOCAL_SESSION_ID, pk_digest, party_records);
    transcript.save(&out_dir.join("transcript.json"))?;
    transcript.verify_internal()?; // never publish an artifact we can't verify

    Ok(DkgRunOutput { transcript })
}
