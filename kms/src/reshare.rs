//! Proactive resharing at epoch boundaries (whitepaper §7.5).
//!
//! Same-committee share refresh over upstream's `reshare_sk_same_set`
//! (v0.13.x — the reason this tag was pinned): every party's share vector is
//! re-randomised, **pk_G is untouched by construction** (the protocol never
//! touches public material), and the union of any old-epoch shares with
//! new-epoch shares is useless — proactive security. The same endpoint doubles
//! as **recovery**: a party entering with `None` obtains a fresh valid share
//! (`--drop-role` demonstrates it).
//!
//! Epoch artifact: `reshare.json` chains to the previous transcript by digest,
//! carries the (invariant) pk_G digest and the NEW per-party share
//! commitments. Verification checks the chain, the pk_G invariant, and that
//! every commitment changed ("old shares dead" at artifact level — the
//! cryptographic statement is the protocol's; the *functional* proof, decrypt
//! same ciphertext before/after, lands with threshold decryption).
//!
//! Honest labels: preprocessing here is `dummy-randoms` (reshare consumes only
//! random sharings; the secure dual-ring offline phase — Z128 AND Z64, each
//! needing its own PRSS — is a documented swap point, same discipline as the DKG's
//! H1). Local runtime + dev share files first; ceremony-node mode follows the
//! H2 pattern when this is green.

use std::fs;
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use algebra::base_ring::{Z64, Z128};
use algebra::galois_rings::common::ResiduePoly;
use threshold_execution::endpoints::reshare_sk::{
    ResharePreprocRequired, ReshareSecretKeys, SecureReshareSecretKeys,
};
use threshold_execution::config::BatchParams;
use threshold_execution::large_execution::offline::SecureLargePreprocessing;
use threshold_execution::online::preprocessing::dummy::DummyPreprocessing;
use threshold_execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use threshold_execution::online::preprocessing::RandomPreprocessing;
use threshold_execution::runtime::sessions::base_session::GenericBaseSessionHandles;
use threshold_execution::runtime::sessions::large_session::LargeSession;
use threshold_execution::runtime::sessions::session_parameters::GenericParameterHandles;
use threshold_execution::runtime::sessions::small_session::SmallSession;
use threshold_execution::small_execution::offline::Preprocessing;
use threshold_execution::tests::helper::tests_and_benches::{
    execute_protocol_large, execute_protocol_small,
};
use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;
use threshold_types::network::NetworkMode;

use crate::config::{CommitteeConfig, ParamsChoice, PreprocMode};
use crate::dkg::dkg_params;
use crate::transcript::{share_file, sha256_hex, PartyRecord, Transcript};
use crate::EXTENSION_DEGREE;

pub const RESHARE_SCHEMA: &str = "celar-reshare-transcript/v0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareTranscript {
    pub schema: String,
    /// Epoch this transcript ESTABLISHES (previous transcript is epoch-1;
    /// the genesis DKG transcript is epoch 0).
    pub epoch: u64,
    /// SHA-256 of the previous transcript file — the chain link.
    pub prev_transcript_sha256: String,
    /// Invariant across epochs; copied from (and checked against) genesis.
    pub pk_g_sha256: String,
    pub committee_parties: usize,
    pub params: String,
    /// "dummy-randoms" until the secure dual-ring offline phase lands.
    pub preprocessing: String,
    /// Party that entered with NO share and recovered one, if any.
    pub recovered_role: Option<usize>,
    /// NEW share commitments (every one must differ from the previous epoch).
    pub parties: Vec<PartyRecord>,
    pub wall_secs: f64,
    pub created_unix: u64,
}

impl ReshareTranscript {
    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    /// Verify this epoch against its predecessor's transcript file
    /// (either the genesis `transcript.json` or a prior `reshare.json`).
    pub fn verify_against_prev(&self, prev_path: &Path) -> Result<()> {
        if self.schema != RESHARE_SCHEMA {
            bail!("unknown schema {:?}", self.schema);
        }
        let prev_bytes = fs::read(prev_path)
            .with_context(|| format!("reading previous transcript {}", prev_path.display()))?;
        let got = sha256_hex(&prev_bytes);
        if got != self.prev_transcript_sha256 {
            bail!(
                "chain broken: previous transcript digest {} != recorded {}",
                got,
                self.prev_transcript_sha256
            );
        }

        // Previous artifact: genesis transcript or earlier reshare.
        let prev_json: serde_json::Value = serde_json::from_slice(&prev_bytes)?;
        let (prev_pk, prev_parties, prev_epoch) = match prev_json["schema"].as_str() {
            Some(s) if s == RESHARE_SCHEMA => {
                let p: ReshareTranscript = serde_json::from_slice(&prev_bytes)?;
                (p.pk_g_sha256.clone(), p.parties.clone(), Some(p.epoch))
            }
            Some(s) if s == crate::transcript::SCHEMA => {
                let p: Transcript = serde_json::from_slice(&prev_bytes)?;
                (p.pk_g_sha256.clone(), p.parties.clone(), None)
            }
            other => bail!("previous transcript has unknown schema {other:?}"),
        };
        if let Some(pe) = prev_epoch {
            if self.epoch != pe + 1 {
                bail!("epoch {} does not follow previous epoch {}", self.epoch, pe);
            }
        } else if self.epoch != 1 {
            bail!("epoch {} chained directly to genesis (expected 1)", self.epoch);
        }

        // §7.5 pk_G invariant.
        if self.pk_g_sha256 != prev_pk {
            bail!(
                "pk_G CHANGED across reshare ({} → {}) — §7.5 invariant violated",
                prev_pk,
                self.pk_g_sha256
            );
        }
        // Old shares dead (artifact level): every commitment must change.
        if self.parties.len() != prev_parties.len() {
            bail!(
                "committee size changed ({} → {}) — same-set reshare cannot do that",
                prev_parties.len(),
                self.parties.len()
            );
        }
        for (new, old) in self.parties.iter().zip(prev_parties.iter()) {
            if new.role != old.role {
                bail!("party roles disagree with previous epoch ({} vs {})", new.role, old.role);
            }
            if new.share_commitment_sha256 == old.share_commitment_sha256 {
                bail!(
                    "party {} share commitment UNCHANGED across reshare — old share not refreshed",
                    new.role
                );
            }
        }
        Ok(())
    }

    /// Recompute the new share commitments from a dev keys directory.
    pub fn verify_against_keys(&self, keys_dir: &Path) -> Result<()> {
        for p in &self.parties {
            let path = keys_dir.join(share_file(p.role));
            let bytes = fs::read(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            if sha256_hex(&bytes) != p.share_commitment_sha256 {
                bail!("share commitment mismatch for party {}", p.role);
            }
        }
        Ok(())
    }
}

fn params_choice_from_name(name: &str) -> Result<ParamsChoice> {
    Ok(match name {
        "PARAMS_TEST_BK_SNS" => ParamsChoice::Test,
        "NIST_PARAMS_P32_SNS_FGLWE" => ParamsChoice::NistP32SnsFglwe,
        other => bail!("unknown params name in transcript: {other:?}"),
    })
}

pub struct ReshareOutput {
    pub transcript: ReshareTranscript,
}

/// Run a same-set proactive reshare locally, from a directory containing the
/// previous epoch's artifact (genesis `transcript.json` or `reshare.json`)
/// plus dev share files, into `out_dir` (new share files + `reshare.json`).
///
/// `drop_role` simulates a party that lost its share: it participates with
/// `None` and must come out with a fresh valid share (the §7.5 recovery
/// property, upstream-tested).
pub async fn run_local_reshare(
    in_dir: &Path,
    out_dir: &Path,
    drop_role: Option<usize>,
    preproc: PreprocMode,
) -> Result<ReshareOutput> {
    // Only two modes exist for resharing: dummy (dev) and secure-large.
    // There has never been a PRSS/secure-small reshare mode, and there will
    // not be one: PRSS cannot reach genesis scale, and epoch rotation is
    // the one operation that MUST run at genesis scale (it resets the §7.2
    // budget). Refuse rather than silently downgrade.
    if preproc == PreprocMode::Secure {
        bail!(
            "reshare has no PRSS/secure-small mode: use --preproc secure-large \
             (real, genesis-capable) or dummy (dev). The PRSS path cannot reach \
             genesis scale and resharing is the operation that must."
        );
    }
    // Previous epoch artifact: prefer reshare.json (later epoch) over genesis.
    let (prev_path, prev_pk, prev_parties_records, prev_params, epoch) = {
        let reshare_path = in_dir.join("reshare.json");
        let genesis_path = in_dir.join("transcript.json");
        if reshare_path.exists() {
            let p = ReshareTranscript::load(&reshare_path)?;
            (reshare_path, p.pk_g_sha256, p.parties, p.params, p.epoch + 1)
        } else {
            let p = Transcript::load(&genesis_path)?;
            (genesis_path, p.pk_g_sha256, p.parties, p.dkg.params, 1)
        }
    };
    let parties = prev_parties_records.len();
    if let Some(d) = drop_role {
        if d == 0 || d > parties {
            bail!("--drop-role {d} out of range 1..={parties}");
        }
    }
    let params_choice = params_choice_from_name(&prev_params)?;
    let cfg = CommitteeConfig {
        parties,
        params: params_choice,
        preprocessing: preproc,
        ..Default::default()
    };
    // validate() carries the n ≥ 4t+1 safety interlock for SecureLarge —
    // the same silent-corruption bound as everywhere else the large offline
    // machinery runs. c=4 dev fixtures need --preproc dummy or c ≥ 5 keys.
    cfg.validate()?;
    fs::create_dir_all(out_dir)?;

    let params = dkg_params(params_choice);
    let in_dir_owned = in_dir.to_path_buf();

    // The dummy-preproc seed must be COMMON to all parties (see NOTE below)
    // but MUST also differ per epoch: DummyPreprocessing is deterministic in
    // (seed, session), and with both fixed the reshare map is IDEMPOTENT —
    // new_share_i = masked_value − r_i with identical r reproduces the
    // previous epoch's shares exactly, so nothing is refreshed and the
    // "commitment unchanged" check fires (observed: epoch1→epoch2 failed
    // while genesis→epoch1 passed, since genesis shares didn't come from
    // this map). Deriving the seed from the previous transcript digest is
    // deterministic, common to all parties, and epoch-unique by the chain.
    let dummy_seed = u64::from_str_radix(&sha256_hex(&fs::read(&prev_path)?)[..16], 16)
        .context("deriving epoch seed from previous transcript digest")?;

    let started = Instant::now();
    let chunk_size = cfg.preproc_chunk;

    let mut results = if preproc == PreprocMode::SecureLarge {
        // ---- SECURE-LARGE: the genesis-capable dual-ring offline phase ----
        // Reshare consumes RANDOMS ONLY, in both rings — no triples — so
        // this is the cheapest of the three secure-large integrations.
        // Chunked exactly as the DKG's (monolithic batches fail in robust
        // reconstruction; upstream never tests above batch 10).
        let in_dir_large = in_dir_owned.clone();
        let mut task = |mut session: LargeSession| {
            let in_dir = in_dir_large.clone();
            async move {
                let role = session.my_role().one_based();
                let mut contribution: Option<PrivateKeySet<EXTENSION_DEGREE>> =
                    if Some(role) == drop_role {
                        None
                    } else {
                        let bytes = fs::read(in_dir.join(share_file(role)))
                            .expect("reading previous-epoch share file (dev keys required)");
                        Some(bincode::deserialize(&bytes).expect("deserializing share"))
                    };

                session
                    .network()
                    .set_timeout_for_next_round(std::time::Duration::from_secs(600))
                    .await;

                let required = ResharePreprocRequired::new(session.num_parties(), params, false);
                let chunk = chunk_size.max(1);

                let mut preproc_128: InMemoryBasePreprocessing<
                    ResiduePoly<Z128, EXTENSION_DEGREE>,
                > = InMemoryBasePreprocessing::default();
                let mut left = required.batch_params_128.randoms;
                while left > 0 {
                    let step = left.min(chunk);
                    let mut out = SecureLargePreprocessing::default()
                        .execute(&mut session, BatchParams { triples: 0, randoms: step })
                        .await
                        .expect("secure large offline (Z128 randoms) failed");
                    preproc_128.append_randoms(
                        out.next_random_vec(step).expect("draining Z128 randoms"),
                    );
                    left -= step;
                }

                let mut preproc_64: InMemoryBasePreprocessing<
                    ResiduePoly<Z64, EXTENSION_DEGREE>,
                > = InMemoryBasePreprocessing::default();
                let mut left = required.batch_params_64.randoms;
                while left > 0 {
                    let step = left.min(chunk);
                    let mut out = SecureLargePreprocessing::default()
                        .execute(&mut session, BatchParams { triples: 0, randoms: step })
                        .await
                        .expect("secure large offline (Z64 randoms) failed");
                    preproc_64.append_randoms(
                        out.next_random_vec(step).expect("draining Z64 randoms"),
                    );
                    left -= step;
                }

                let new_share = SecureReshareSecretKeys::reshare_sk_same_set(
                    &mut session,
                    &mut preproc_128,
                    &mut preproc_64,
                    &mut contribution,
                    params,
                    false,
                )
                .await
                .expect("reshare protocol failed");

                (role, new_share)
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
    } else {
        // ---- DUMMY (dev): the original small-session path, unchanged ----
        let mut task = |mut session: SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
                        _info: Option<String>| {
        let in_dir = in_dir_owned.clone();
        async move {
            let role = session.my_role().one_based();

            // Same round-timeout discipline as the DKG paths (H1 finding).
            session
                .network()
                .set_timeout_for_next_round(std::time::Duration::from_secs(600))
                .await;

            // My previous-epoch share — or None if simulating loss/recovery.
            let mut contribution: Option<PrivateKeySet<EXTENSION_DEGREE>> =
                if Some(role) == drop_role {
                    None
                } else {
                    let bytes = fs::read(in_dir.join(share_file(role)))
                        .expect("reading previous-epoch share file (dev keys required)");
                    Some(bincode::deserialize(&bytes).expect("deserializing share"))
                };

            // Reshare consumes RANDOM sharings only, in both rings; sized by
            // upstream's own accounting. Randoms come from DummyPreprocessing
            // (ring-generic) — the secure offline swap point is documented in
            // the module docs.
            // NOTE: the dummy seed must be COMMON to all parties — upstream's
            // DummyPreprocessing derives the full sharing of a seed-determined
            // value and hands each party its own share; differing seeds would
            // produce "shares" of nothing consistent and robust opening fails.
            // It is epoch-unique by derivation (see run_local_reshare) or the
            // reshare would be idempotent. This is dev-only.
            // (0.13.22 → main: new `oprf_key_present` flag — false for our
            // keysets, which predate dedicated OPRF keys.)
            let required = ResharePreprocRequired::new(session.num_parties(), params, false);
            let mut dummy = DummyPreprocessing::new(dummy_seed, &session);
            let mut preproc_128: InMemoryBasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> =
                InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: RandomPreprocessing::<
                        ResiduePoly<Z128, EXTENSION_DEGREE>,
                    >::next_random_vec(
                        &mut dummy, required.batch_params_128.randoms
                    )
                    .expect("z128 randoms"),
                };
            let mut preproc_64: InMemoryBasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>> =
                InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: RandomPreprocessing::<
                        ResiduePoly<Z64, EXTENSION_DEGREE>,
                    >::next_random_vec(
                        &mut dummy, required.batch_params_64.randoms
                    )
                    .expect("z64 randoms"),
                };

            let new_share = SecureReshareSecretKeys::reshare_sk_same_set(
                &mut session,
                &mut preproc_128,
                &mut preproc_64,
                &mut contribution,
                params,
                // oprf_key_present: our keysets have no dedicated OPRF key.
                false,
            )
            .await
            .expect("reshare protocol failed");

                (role, new_share)
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
    };
    let wall_secs = started.elapsed().as_secs_f64();

    if results.len() != parties {
        bail!("only {}/{} parties completed the reshare", results.len(), parties);
    }
    results.sort_by_key(|(role, _)| *role);

    // New share files + commitments.
    let mut party_records = Vec::with_capacity(parties);
    for (role, share) in &results {
        let bytes = bincode::serialize(share).context("serializing new share")?;
        party_records.push(PartyRecord {
            role: *role,
            share_commitment_sha256: sha256_hex(&bytes),
        });
        fs::write(out_dir.join(share_file(*role)), &bytes)?;
    }
    fs::write(
        out_dir.join("DEV-KEYS-WARNING.txt"),
        "Reshared key material written by a DEV run for transcript\n\
         re-verification. A real ceremony never persists shares unprotected.\n",
    )?;

    let transcript = ReshareTranscript {
        schema: RESHARE_SCHEMA.to_string(),
        epoch,
        prev_transcript_sha256: sha256_hex(&fs::read(&prev_path)?),
        pk_g_sha256: prev_pk,
        committee_parties: parties,
        params: prev_params,
        preprocessing: match preproc {
            PreprocMode::SecureLarge => "secure-large-randoms".to_string(),
            _ => "dummy-randoms".to_string(),
        },
        recovered_role: drop_role,
        parties: party_records,
        wall_secs,
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    transcript.save(&out_dir.join("reshare.json"))?;
    // Never publish an artifact we can't verify — full chain check now.
    transcript.verify_against_prev(&prev_path)?;
    transcript.verify_against_keys(out_dir)?;

    Ok(ReshareOutput { transcript })
}
