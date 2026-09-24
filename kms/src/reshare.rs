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
use threshold_execution::runtime::sessions::base_session::{BaseSession, GenericBaseSession};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_execution::tests::helper::tests_and_benches::execute_protocol_two_sets;
use threshold_types::role::{TwoSetsRole, TwoSetsThreshold};
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
    session_threshold: Option<usize>,
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
        session_threshold,
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

// ---------------------------------------------------------------------------
// Upward key-reshare (two-sets): reshare a key held by an old committee at
// degree t1 UP to a new committee at a higher degree t2. This is what lets a
// key live at a degree decoupled from (higher than) the committee's corruption
// threshold; the flooding masks are supplied separately at the same degree.
//
// Cut 1 (this): the protocol driver + a wiring round-trip test on dummy
// preprocessing. The production layer (secure preprocessing, share-file I/O,
// the epoch artifact at the new degree, the celar-dkg subcommand) and the
// end-to-end key-preservation proof (decrypt with the reshared key) follow on
// the same branch. Deep correctness of the two-sets protocol itself — that the
// reshared shares reconstruct the same key — is proven by the upstream
// `simulate_reshare_two_sets` test; this verifies OUR driver runs it and yields
// well-formed set-2 shares.
// ---------------------------------------------------------------------------

/// Drive an upward two-sets reshare of a key held by set 1 (`old_shares`, one
/// per set-1 party at degree `t1`) up to `parties_s2` parties at degree `t2`
/// (`intersection` parties in both sets), on dummy preprocessing. Returns set-2's
/// new key shares.
///
/// `old_shares[i]` is set-1 party `i+1`'s share — in a deployment these are
/// loaded from the previous epoch's files; the file wrapper and the test both
/// supply them this way, which is what makes this the reusable driver.
#[allow(clippy::too_many_arguments)]
pub async fn run_upward_reshare(
    old_shares: Vec<PrivateKeySet<EXTENSION_DEGREE>>,
    params: DKGParams,
    t1: usize,
    parties_s2: usize,
    t2: usize,
    intersection: usize,
) -> Result<Vec<PrivateKeySet<EXTENSION_DEGREE>>> {
    let parties_s1 = old_shares.len();
    let oprf_present = old_shares
        .first()
        .map(|s| s.oprf_secret_key_share.is_some())
        .unwrap_or(false);
    let threshold = TwoSetsThreshold {
        threshold_set_1: t1 as u8,
        threshold_set_2: t2 as u8,
    };

    let mut task = |mut common: GenericBaseSession<TwoSetsRole>,
                    session_s1: Option<BaseSession>,
                    session_s2: Option<BaseSession>| {
        let old_shares = old_shares.clone();
        async move {
            let my_two_sets_role = common.my_role();
            // Set-2 parties carry a plain set-2 Role in their own base session —
            // capture it now, before that session is moved into the reshare call,
            // so the returned share can be filed under its set-2 index.
            let set2_role = session_s2.as_ref().map(|s| s.my_role().one_based());

            let mut my_share: Option<PrivateKeySet<EXTENSION_DEGREE>> = session_s1
                .as_ref()
                .map(|s1| {
                    s1.my_role()
                        .get_from(&old_shares)
                        .expect("my set-1 share")
                        .clone()
                });

            // Set-2 preprocessing: dummy randoms sized by upstream's accounting.
            let (mut preproc_64, mut preproc_128) = if let Some(s2) = session_s2.as_ref() {
                let mut dp = DummyPreprocessing::new(42, s2);
                let n_s1 = common.roles().iter().filter(|p| p.is_set1()).count();
                let req = ResharePreprocRequired::new(n_s1, params, oprf_present);
                let p64 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: dp
                        .next_random_vec(req.batch_params_64.randoms)
                        .expect("Z64 randoms"),
                };
                let p128 = InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: dp
                        .next_random_vec(req.batch_params_128.randoms)
                        .expect("Z128 randoms"),
                };
                (Some(p64), Some(p128))
            } else {
                (None, None)
            };

            let out: Option<PrivateKeySet<EXTENSION_DEGREE>> = match my_two_sets_role {
                TwoSetsRole::OnlySet1(_) => {
                    SecureReshareSecretKeys::reshare_sk_two_sets_as_s1(
                        &mut common,
                        my_share.as_mut().unwrap(),
                        params,
                        oprf_present,
                    )
                    .await
                    .expect("reshare as set 1");
                    None
                }
                TwoSetsRole::OnlySet2(_) => Some(
                    SecureReshareSecretKeys::reshare_sk_two_sets_as_s2(
                        &mut (common, session_s2.unwrap()),
                        preproc_128.as_mut().unwrap(),
                        preproc_64.as_mut().unwrap(),
                        params,
                        oprf_present,
                    )
                    .await
                    .expect("reshare as set 2"),
                ),
                TwoSetsRole::Both(_) => Some(
                    SecureReshareSecretKeys::reshare_sk_two_sets_as_both_sets(
                        &mut (common, session_s2.unwrap()),
                        preproc_128.as_mut().unwrap(),
                        preproc_64.as_mut().unwrap(),
                        my_share.as_mut().unwrap(),
                        params,
                        oprf_present,
                    )
                    .await
                    .expect("reshare as both sets"),
                ),
            };

            (set2_role, out)
        }
    };

    let results = execute_protocol_two_sets::<_, _, ResiduePoly<Z128, EXTENSION_DEGREE>, EXTENSION_DEGREE>(
        parties_s1,
        parties_s2,
        intersection,
        threshold,
        None,
        NetworkMode::Sync,
        &mut task,
    )
    .await;

    // Set-2 parties (OnlySet2 and Both) return their new share indexed by set-2
    // role; set-1-only parties return None. Return the shares in set-2 role order
    // so the caller can file each under `share_file(role)`.
    let mut collected: Vec<(usize, PrivateKeySet<EXTENSION_DEGREE>)> = results
        .into_iter()
        .filter_map(|(idx, share)| match (idx, share) {
            (Some(i), Some(s)) => Some((i, s)),
            _ => None,
        })
        .collect();
    collected.sort_by_key(|(i, _)| *i);
    Ok(collected.into_iter().map(|(_, s)| s).collect())
}

pub const UPWARD_RESHARE_SCHEMA: &str = "celar-upward-reshare-transcript/v0";

/// Artifact for an UPWARD reshare. Unlike a same-set reshare, both the committee
/// and the sharing degree change (an `old_committee_parties`-party set at
/// `old_degree` becomes a `new_committee_parties`-party set at `new_degree`), so
/// this cannot reuse [`ReshareTranscript`], whose verification hard-rejects a
/// committee change. What stays invariant is pk_G: resharing never touches public
/// material, so the key — and therefore its public key — is unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpwardReshareTranscript {
    pub schema: String,
    pub prev_transcript_sha256: String,
    pub pk_g_sha256: String,
    pub old_committee_parties: usize,
    pub new_committee_parties: usize,
    pub old_degree: usize,
    pub new_degree: usize,
    pub params: String,
    pub preprocessing: String,
    /// The NEW committee's share commitments.
    pub parties: Vec<PartyRecord>,
    pub wall_secs: f64,
    pub created_unix: u64,
}

impl UpwardReshareTranscript {
    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    /// Verify against the previous epoch: schema, the chain digest, the pk_G
    /// invariant, and that the degree actually rose. The committee and degree
    /// are EXPECTED to change, so those are recorded rather than rejected.
    pub fn verify_against_prev(&self, prev_path: &Path) -> Result<()> {
        if self.schema != UPWARD_RESHARE_SCHEMA {
            bail!("unknown schema {:?}", self.schema);
        }
        let prev_bytes = fs::read(prev_path)
            .with_context(|| format!("reading previous transcript {}", prev_path.display()))?;
        if sha256_hex(&prev_bytes) != self.prev_transcript_sha256 {
            bail!("chain broken: previous transcript digest does not match recorded");
        }
        // Every artifact type carries pk_g_sha256 at the top level.
        let prev_json: serde_json::Value = serde_json::from_slice(&prev_bytes)?;
        let prev_pk = prev_json["pk_g_sha256"]
            .as_str()
            .context("previous transcript has no pk_g_sha256")?;
        if self.pk_g_sha256 != prev_pk {
            bail!("pk_G CHANGED across upward reshare — §7.5 invariant violated");
        }
        if self.new_degree <= self.old_degree {
            bail!(
                "an upward reshare must raise the degree ({} -> {})",
                self.old_degree,
                self.new_degree
            );
        }
        Ok(())
    }

    pub fn verify_against_keys(&self, keys_dir: &Path) -> Result<()> {
        for p in &self.parties {
            let bytes = fs::read(keys_dir.join(share_file(p.role)))?;
            if sha256_hex(&bytes) != p.share_commitment_sha256 {
                bail!("share commitment mismatch for party {}", p.role);
            }
        }
        Ok(())
    }
}

/// Run an upward reshare locally: read the previous epoch's artifact + dev share
/// files from `in_dir`, reshare the key up to a `new_parties`-party committee at
/// degree `new_threshold` (`intersection` parties in both sets), and write the
/// new share files + `upward-reshare.json` into `out_dir`. Dummy preprocessing
/// (dev); the secure-large offline phase is a documented follow-on.
pub async fn run_local_upward_reshare(
    in_dir: &Path,
    out_dir: &Path,
    new_parties: usize,
    new_threshold: usize,
    intersection: usize,
) -> Result<UpwardReshareTranscript> {
    // Previous epoch: prefer a reshare artifact, else the genesis transcript.
    let (prev_path, prev_pk, old_parties, prev_params, old_degree) = {
        let reshare_path = in_dir.join("reshare.json");
        let genesis_path = in_dir.join("transcript.json");
        if reshare_path.exists() {
            let p = ReshareTranscript::load(&reshare_path)?;
            // A same-set reshare leaves the sharing at the committee's threshold.
            let d = CommitteeConfig { parties: p.committee_parties, ..Default::default() }
                .session_threshold();
            (reshare_path, p.pk_g_sha256, p.committee_parties, p.params, d)
        } else {
            let p = Transcript::load(&genesis_path)?;
            // Reconstruct at the genesis's ACTUAL recorded threshold, not the
            // ⌊(c−1)/3⌋ default. The secure reshare robust-opens degree-2t values
            // and so needs c ≥ 4t+1 (t ≤ ⌊(c−1)/4⌋), meaning a reshareable genesis
            // is keyed below the default; assuming the default degree makes the
            // set-1 reconstruction fail on exactly those (correct) low-t keys.
            let d = p.committee.session_threshold;
            (genesis_path, p.pk_g_sha256, p.parties.len(), p.dkg.params, d)
        }
    };
    let params_choice = params_choice_from_name(&prev_params)?;
    let params = dkg_params(params_choice);

    // Load the old committee's shares (set 1) from files, in role order.
    let mut old_shares: Vec<PrivateKeySet<EXTENSION_DEGREE>> = Vec::with_capacity(old_parties);
    for role in 1..=old_parties {
        let bytes = fs::read(in_dir.join(share_file(role)))
            .with_context(|| format!("reading previous-epoch share for party {role}"))?;
        old_shares.push(bincode::deserialize(&bytes).context("deserializing share")?);
    }

    fs::create_dir_all(out_dir)?;
    let started = Instant::now();
    let new_shares = run_upward_reshare(
        old_shares,
        params,
        old_degree,
        new_parties,
        new_threshold,
        intersection,
    )
    .await?;
    let wall_secs = started.elapsed().as_secs_f64();

    if new_shares.len() != new_parties {
        bail!(
            "only {}/{} new-committee parties produced a share",
            new_shares.len(),
            new_parties
        );
    }

    let mut party_records = Vec::with_capacity(new_parties);
    for (i, share) in new_shares.iter().enumerate() {
        let role = i + 1;
        let bytes = bincode::serialize(share).context("serializing new share")?;
        party_records.push(PartyRecord {
            role,
            share_commitment_sha256: sha256_hex(&bytes),
        });
        fs::write(out_dir.join(share_file(role)), &bytes)?;
    }
    fs::write(
        out_dir.join("DEV-KEYS-WARNING.txt"),
        "Upward-reshared key material written by a DEV run for transcript\n\
         re-verification. A real ceremony never persists shares unprotected.\n",
    )?;

    let transcript = UpwardReshareTranscript {
        schema: UPWARD_RESHARE_SCHEMA.to_string(),
        prev_transcript_sha256: sha256_hex(&fs::read(&prev_path)?),
        pk_g_sha256: prev_pk,
        old_committee_parties: old_parties,
        new_committee_parties: new_parties,
        old_degree,
        new_degree: new_threshold,
        params: prev_params,
        preprocessing: "dummy-randoms".to_string(),
        parties: party_records,
        wall_secs,
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    transcript.save(&out_dir.join("upward-reshare.json"))?;
    transcript.verify_against_prev(&prev_path)?;
    transcript.verify_against_keys(out_dir)?;
    Ok(transcript)
}

#[cfg(test)]
mod upward_reshare_tests {
    use super::*;
    use rand::SeedableRng;
    use threshold_execution::tfhe_internals::test_feature::{
        gen_uncompressed_key_set, keygen_all_party_shares_from_client_key,
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn upward_reshare_produces_well_formed_set2_shares() {
        // Small test params; upward from (7 parties, degree 2) to (8 parties,
        // degree 3) — degree INCREASES, the decoupling shape, and the exact
        // config the fork's high-degree two-sets test proves preserves the key.
        // Here we verify OUR driver runs the protocol and yields one well-formed
        // share per set-2 party.
        let params = dkg_params(ParamsChoice::Test);
        let mut rng = aes_prng::AesRng::seed_from_u64(7);
        let keyset = gen_uncompressed_key_set(params, tfhe::Tag::default(), &mut rng);
        let old_shares = keygen_all_party_shares_from_client_key::<_, EXTENSION_DEGREE>(
            &keyset.client_key,
            params.classic_pbs(),
            &mut rng,
            7, // parties_s1
            2, // t1
        )
        .expect("sharing the old key");

        let new_shares = run_upward_reshare(
            old_shares, params, 2, // t1
            8, // parties_s2
            3, // t2
            0, // intersection
        )
        .await
        .expect("upward reshare");

        assert_eq!(
            new_shares.len(),
            8,
            "one new share per set-2 party (degree 3 on 8 parties)"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_upward_reshare_round_trips_over_files() {
        // Build a previous-epoch fixture on disk (the old committee's share
        // files + a reshare.json), upward-reshare it to a larger committee at a
        // higher degree, and confirm the new committee's share files and the
        // degree-change artifact are written and verify. This is the file
        // round-trip the runner is used through in practice.
        let params = dkg_params(ParamsChoice::Test);
        let mut rng = aes_prng::AesRng::seed_from_u64(9);
        let keyset = gen_uncompressed_key_set(params, tfhe::Tag::default(), &mut rng);

        let old_parties = 7usize;
        // Share the old key at the SAME degree the runner derives (the old
        // committee's session threshold), so the shares it loads line up.
        let old_degree = CommitteeConfig {
            parties: old_parties,
            ..Default::default()
        }
        .session_threshold();
        let old_shares = keygen_all_party_shares_from_client_key::<_, EXTENSION_DEGREE>(
            &keyset.client_key,
            params.classic_pbs(),
            &mut rng,
            old_parties,
            old_degree,
        )
        .expect("share old key");

        let stamp = std::process::id();
        let in_dir = std::env::temp_dir().join(format!("celar-upward-{stamp}-in"));
        let out_dir = std::env::temp_dir().join(format!("celar-upward-{stamp}-out"));
        fs::create_dir_all(&in_dir).unwrap();

        for (i, s) in old_shares.iter().enumerate() {
            fs::write(in_dir.join(share_file(i + 1)), bincode::serialize(s).unwrap()).unwrap();
        }
        // Minimal previous-epoch artifact (a same-set reshare.json).
        let prev = ReshareTranscript {
            schema: RESHARE_SCHEMA.to_string(),
            epoch: 1,
            prev_transcript_sha256: "genesis".to_string(),
            pk_g_sha256: "pkg-fixture".to_string(),
            committee_parties: old_parties,
            params: "PARAMS_TEST_BK_SNS".to_string(),
            preprocessing: "dummy-randoms".to_string(),
            recovered_role: None,
            parties: (1..=old_parties)
                .map(|r| PartyRecord {
                    role: r,
                    share_commitment_sha256: "c".to_string(),
                })
                .collect(),
            wall_secs: 0.0,
            created_unix: 0,
        };
        prev.save(&in_dir.join("reshare.json")).unwrap();

        // Upward to 8 parties at degree old_degree+1 (strictly upward); for the
        // expected old degree of 2 this is the 8/3 config proven above.
        let new_parties = 8usize;
        let new_threshold = old_degree + 1;
        let t = run_local_upward_reshare(&in_dir, &out_dir, new_parties, new_threshold, 0)
            .await
            .expect("upward reshare over files");

        assert_eq!(t.old_committee_parties, old_parties);
        assert_eq!(t.new_committee_parties, new_parties);
        assert_eq!(t.new_degree, new_threshold);
        assert_eq!(t.pk_g_sha256, "pkg-fixture", "pk_G invariant carried forward");
        for r in 1..=new_parties {
            assert!(out_dir.join(share_file(r)).exists(), "new share {r} written");
        }
        // The runner verified the artifact internally; re-verify the on-disk one.
        UpwardReshareTranscript::load(&out_dir.join("upward-reshare.json"))
            .unwrap()
            .verify_against_keys(&out_dir)
            .unwrap();

        let _ = fs::remove_dir_all(&in_dir);
        let _ = fs::remove_dir_all(&out_dir);
    }
}
