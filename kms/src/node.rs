//! H2: the ceremony node — one OS process per committee member, gRPC/mTLS
//! between members (the S2 transport decision), running the fixed genesis-DKG
//! phase sequence:
//!
//!   serve mTLS ⇄ connect to peers → [SYNC session sid] PRSS init → secure
//!   offline phase → fill DKG preprocessing → [ASYNC session sid+1]
//!   distributed keygen → write transcript fragment
//!
//! The two-session split mirrors upstream production (core/service): Sync
//! mode is only sound for the broadcast-based phases; the online keygen's
//! robust opens MUST run in Async mode, or round-deadline races make
//! parties reconstruct from different share subsets and derive different
//! pk_G with no detectable corruption (H2 root cause, 2026-08-17).
//!
//! No choreographer: every node runs the same deterministic sequence from its
//! config. The operator collects the n fragments and `collect`s them into the
//! canonical transcript (pk_G equality across fragments is the group-key
//! property, checked at collection).
//!
//! This is deliberately the seed of the real Celar KMS daemon: B2/B3 add
//! request-serving endpoints on top of exactly this networking + session
//! stack; the DKG ceremony is its first (one-shot) mode.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use aes_prng::AesRng;
use algebra::base_ring::Z128;
use algebra::galois_rings::common::ResiduePoly;
use threshold_execution::config::BatchParams;
use threshold_execution::endpoints::keygen::{
    OnlineDistributedKeyGen, SecureOnlineDistributedKeyGen128,
};
use threshold_execution::keyset_config::KeySetConfig;
use threshold_execution::online::preprocessing::{create_memory_factory, DKGPreprocessing};
use threshold_execution::runtime::sessions::base_session::{
    BaseSession, GenericBaseSessionHandles, ToBaseSession,
};
use threshold_execution::runtime::sessions::small_session::SmallSession;
use threshold_execution::runtime::sessions::session_parameters::SessionParameters;
use threshold_execution::online::preprocessing::RandomPreprocessing;
use threshold_execution::sharing::open::{RobustOpen, SecureRobustOpen};
use threshold_execution::small_execution::offline::{Preprocessing, SecureSmallPreprocessing};
use threshold_execution::small_execution::prss::{DerivePRSSState, PRSSInit, RobustSecurePrssInit};
use threshold_networking::grpc::{GrpcNetworkingManager, TlsExtensionGetter};
use threshold_types::network::NetworkMode;
use threshold_types::party::{Identity, RoleAssignment};
use threshold_types::role::Role;
use threshold_types::session_id::SessionId;
use tokio_rustls::rustls::client::ClientConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::RootCertStore;
use tonic::transport::{Server, ServerTlsConfig};
use x509_parser::pem::parse_x509_pem;

use crate::config::CommitteeConfig;
use crate::transcript::sha256_hex;
use crate::EXTENSION_DEGREE;

type Poly = ResiduePoly<Z128, EXTENSION_DEGREE>;

// ---------------------------------------------------------------- config

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsPaths {
    /// This node's certificate (PEM).
    pub cert: String,
    /// This node's private key (PEM).
    pub key: String,
    /// Comma-separated list of CA cert paths (every committee member's CA).
    pub calist: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    /// One-based role index.
    pub role: usize,
    /// DNS name used to DIAL the peer (endpoint URL is host:port).
    pub host: String,
    pub port: u16,
    /// MPC identity = the peer's TLS cert subject/SAN. Used as BOTH the TLS
    /// server-name verified on connect AND the key inbound message queues
    /// are looked up by. Defaults to `host` when omitted — set it explicitly
    /// when the cert subject differs from the dial name (e.g. upstream's
    /// generator issues core certs as "party1-core1" under CA "party1").
    #[serde(default)]
    pub mpc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's one-based role. Must appear in `peers`.
    pub role: usize,
    /// Bind address for the MPC server (default 0.0.0.0).
    #[serde(default = "default_listen")]
    pub listen_addr: String,
    /// ALL committee members including self (host/port as peers dial them).
    pub peers: Vec<PeerEntry>,
    pub tls: TlsPaths,
    pub committee: CommitteeConfig,
    /// Ceremony session id (must match across nodes). The node uses TWO
    /// derived MPC sessions: `session_id` for the sync phases (PRSS init +
    /// offline preprocessing + fill) and `session_id + 1` for the async
    /// online keygen — so leave a gap between ceremonies' ids.
    #[serde(default = "default_session_id")]
    pub session_id: u64,
    /// Per-round network timeout — load-bearing (H1 finding: heavy compute
    /// between rounds must not get shares dropped).
    #[serde(default = "default_round_timeout")]
    pub round_timeout_secs: u64,
    /// Grace period for all peers to come up before the protocol starts.
    #[serde(default = "default_startup_wait")]
    pub startup_wait_secs: u64,
    pub out_dir: PathBuf,
    #[serde(default)]
    pub write_dev_keys: bool,
    /// B6: path to the vetted committee roster governing this ceremony.
    /// When set, the node validates the roster (§7.7 rules for genesis mode),
    /// checks its OWN entry and every peer against it, verifies the TLS
    /// trust-root set matches the roster's CA pins exactly, and stamps the
    /// roster digest into its transcript fragment.
    #[serde(default)]
    pub roster: Option<PathBuf>,
}

fn default_listen() -> String {
    "0.0.0.0".into()
}
fn default_session_id() -> u64 {
    1
}
fn default_round_timeout() -> u64 {
    600
}
fn default_startup_wait() -> u64 {
    5
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading node config {}", path.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn validate(&self) -> Result<()> {
        self.committee.validate()?;
        if self.peers.len() != self.committee.parties {
            bail!(
                "config lists {} peers but committee size is {}",
                self.peers.len(),
                self.committee.parties
            );
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.peers {
            if p.role == 0 || p.role > self.committee.parties {
                bail!("peer role {} out of range 1..={}", p.role, self.committee.parties);
            }
            if !seen.insert(p.role) {
                bail!("duplicate peer role {}", p.role);
            }
        }
        if !seen.contains(&self.role) {
            bail!("this node's role {} is not in the peer list", self.role);
        }
        Ok(())
    }

    fn my_peer(&self) -> &PeerEntry {
        self.peers
            .iter()
            .find(|p| p.role == self.role)
            .expect("validated: role in peers")
    }
}

// ---------------------------------------------------------------- fragment

/// What one node contributes to the ceremony transcript. Public: it carries
/// the pk_G digest and a hash COMMITMENT to this node's share vector only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptFragment {
    pub schema: String,
    pub role: usize,
    pub committee_parties: usize,
    pub session_id: u64,
    pub params: String,
    pub tag: String,
    pub pk_g_sha256: String,
    pub share_commitment_sha256: String,
    pub wall_secs: f64,
    pub transport: String,
    /// B6: digest of the roster this node ran under (None = dev, rosterless).
    #[serde(default)]
    pub roster_sha256: Option<String>,
}

pub const FRAGMENT_SCHEMA: &str = "celar-dkg-fragment/v0";

pub fn fragment_file(role: usize) -> String {
    format!("fragment_{role:03}.json")
}

// ---------------------------------------------------------------- TLS

/// Mirror of upstream's PartyConf::get_client_tls_conf — rustls client config
/// with our identity for mTLS and every member's CA as trust root.
fn build_client_tls(tls: &TlsPaths) -> Result<ClientConfig> {
    let cert_bytes = fs::read_to_string(&tls.cert).context("reading node cert")?;
    let cert = parse_x509_pem(cert_bytes.as_ref())?.1;
    let cert_chain = vec![CertificateDer::from_slice(cert.contents.as_slice()).into_owned()];

    let key_bytes = fs::read_to_string(&tls.key).context("reading node key")?;
    let key = parse_x509_pem(key_bytes.as_ref())?.1;
    let key_der = PrivateKeyDer::try_from(key.contents.as_slice())
        .map_err(|e| anyhow::anyhow!("could not parse TLS private key: {e}"))?
        .clone_key();

    let mut roots = RootCertStore::empty();
    for path in tls.calist.split(',').filter(|s| !s.is_empty()) {
        let ca_bytes =
            fs::read_to_string(path).with_context(|| format!("reading CA {path}"))?;
        let ca = parse_x509_pem(ca_bytes.as_ref())?.1;
        roots.add(CertificateDer::from_slice(ca.contents.as_slice()).into_owned())?;
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key_der)?)
}

fn server_tls(tls: &TlsPaths) -> Result<ServerTlsConfig> {
    let cert = fs::read_to_string(&tls.cert)?;
    let key = fs::read_to_string(&tls.key)?;
    let identity = tonic::transport::Identity::from_pem(cert, key);
    let mut ca_pem = String::new();
    for path in tls.calist.split(',').filter(|s| !s.is_empty()) {
        ca_pem.push_str(&fs::read_to_string(path)?);
        ca_pem.push('\n');
    }
    Ok(ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(tonic::transport::Certificate::from_pem(ca_pem)))
}

// ---------------------------------------------------------------- ceremony

/// Run this node's side of the genesis DKG ceremony. Blocks until the
/// protocol completes; returns the fragment (also written to out_dir).
pub async fn run_ceremony(cfg: &NodeConfig) -> Result<TranscriptFragment> {
    cfg.validate()?;

    // B6: enforce the vetted roster before any networking happens.
    let roster_sha256 = match &cfg.roster {
        None => None,
        Some(path) => {
            let roster = crate::committee::CommitteeRoster::load(path)?; // validates §7.7 rules
            if roster.parties() != cfg.committee.parties {
                bail!(
                    "roster has {} members but committee config says {}",
                    roster.parties(),
                    cfg.committee.parties
                );
            }
            // My own entry and every peer must match the roster exactly.
            for peer in &cfg.peers {
                let member = roster
                    .members
                    .iter()
                    .find(|m| m.role == peer.role)
                    .with_context(|| format!("peer role {} not in the roster", peer.role))?;
                let peer_mpc = peer.mpc.clone().unwrap_or_else(|| peer.host.clone());
                if member.host != peer.host
                    || member.port != peer.port
                    || member.mpc_identity != peer_mpc
                {
                    bail!(
                        "peer {} deviates from the vetted roster (config {}:{} mpc {:?} \
                         vs roster {}:{} mpc {:?}) — refusing to key with an unvetted party",
                        peer.role, peer.host, peer.port, peer_mpc,
                        member.host, member.port, member.mpc_identity
                    );
                }
            }
            // Trust roots must be EXACTLY the roster's pinned CA set.
            let ca_paths: Vec<String> = cfg
                .tls
                .calist
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            roster.verify_ca_set(&ca_paths)?;
            eprintln!(
                "celar-kms-node[{}]: roster VERIFIED ({} vetted members, quorum {}, digest {})",
                cfg.role,
                roster.parties(),
                roster.reconstruction_quorum(),
                &roster.digest()?[..16],
            );
            Some(roster.digest()?)
        }
    };

    fs::create_dir_all(&cfg.out_dir)?;
    let my_role = Role::indexed_from_one(cfg.role);
    let sid = SessionId::from(cfg.session_id as u128);

    // 1) mTLS networking: server for inbound, manager for outbound.
    // (0.13.22 → main: `new` now takes (tls, CoreToCoreNetworkConfig); the
    // testing-only force_tls bool is gone. Default() = all-None fields, every
    // accessor falls back to upstream constants — same as the old None.)
    let client_tls = build_client_tls(&cfg.tls)?;
    let manager = Arc::new(GrpcNetworkingManager::new(
        Some(client_tls),
        threshold_networking::grpc::CoreToCoreNetworkConfig::default(),
    )?);
    let mpc_service = manager.new_server(TlsExtensionGetter::TlsConnectInfo);

    let bind = format!("{}:{}", cfg.listen_addr, cfg.my_peer().port);
    let server_tls_cfg = server_tls(&cfg.tls)?;
    let server_handle = tokio::spawn(
        Server::builder()
            .tls_config(server_tls_cfg)?
            .http2_adaptive_window(Some(true))
            .add_service(mpc_service)
            .serve(bind.parse().context("parsing bind address")?),
    );
    eprintln!("celar-kms-node[{}]: mTLS MPC server on {bind}", cfg.role);

    // 2) let every member come up before dialing out.
    tokio::time::sleep(Duration::from_secs(cfg.startup_wait_secs)).await;

    // 3) session over the real network.
    // The explicit MpcIdentity is LOAD-BEARING: inbound message queues are
    // keyed by it, and the receiving server attributes senders by the TLS
    // cert subject/SAN (hostname, NO port). Leaving it None keys queues as
    // "host:port", so every inbound message is dropped and all parties hang
    // in "Still waiting to receive" (H2 finding, 2026-08-16).
    let assignment: RoleAssignment<Role> = HashMap::from_iter(cfg.peers.iter().map(|p| {
        (
            Role::indexed_from_one(p.role),
            Identity::new(
                p.host.clone(),
                p.port,
                // Option<String>: Identity::new wraps it in MpcIdentity.
                // Must equal the peer's TLS cert subject/SAN — it is BOTH the
                // server-name verified on connect and the inbound-queue key
                // (see PeerEntry::mpc; upstream's None-default "host:port"
                // matches no certificate).
                Some(p.mpc.clone().unwrap_or_else(|| p.host.clone())),
            ),
        )
    }))
    .into();
    let role_set: std::collections::HashSet<Role> = assignment.keys().cloned().collect();

    // SYNC session: PRSS init (broadcast assumes synchrony), the secure
    // offline phase, and the DKG-preprocessing fill — mirroring upstream
    // production, which runs PRSS/broadcast/preprocessing in Sync mode.
    let networking = manager
        .make_network_session(sid, &assignment, my_role, NetworkMode::Sync)
        .await
        .context("creating the network session (are all peers reachable?)")?;
    let params = SessionParameters::new(
        cfg.committee.session_threshold() as u8,
        sid,
        my_role,
        role_set.clone(),
    )
    .map_err(|e| anyhow::anyhow!("session parameters: {e:?}"))?;
    let mut base = BaseSession::new(params, networking, AesRng::from_random_seed())
        .map_err(|e| anyhow::anyhow!("base session: {e:?}"))?;

    let started = Instant::now();

    // 4) PRSS init — interactive, one-time for this ceremony epoch.
    base.network()
        .set_timeout_for_next_round(Duration::from_secs(cfg.round_timeout_secs))
        .await;
    eprintln!("celar-kms-node[{}]: PRSS init…", cfg.role);
    let prss_setup = RobustSecurePrssInit::default()
        .init(&mut base)
        .await
        .map_err(|e| anyhow::anyhow!("PRSS init failed: {e:?}"))?;
    let prss_state = prss_setup.new_prss_session_state(sid);
    let mut session = SmallSession::<Poly>::new_from_prss_state(base, prss_state)
        .map_err(|e| anyhow::anyhow!("small session: {e:?}"))?;

    // 5) phases identical to the local secure path (H1).
    let params_dkg = match cfg.committee.params {
        crate::config::ParamsChoice::Test => {
            threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS
        }
        crate::config::ParamsChoice::NistP32SnsFglwe => {
            threshold_execution::tfhe_internals::parameters::NIST_PARAMS_P32_SNS_FGLWE
        }
    };
    let keyset_config = KeySetConfig::default();
    // (0.13.22 → main: DKGParamsBasics handle gone; methods inherent.)
    let batch = BatchParams {
        triples: params_dkg.total_triples_required(keyset_config),
        // +2 spare randoms: consumed by the divergence CANARIES below (one
        // opened in the sync session, one in the async session). The fill
        // consumes by count, so identical popping on all nodes stays aligned.
        randoms: params_dkg.total_randomness_required(keyset_config) + 2,
    };

    session
        .network()
        .set_timeout_for_next_round(Duration::from_secs(cfg.round_timeout_secs))
        .await;
    eprintln!("celar-kms-node[{}]: secure offline phase…", cfg.role);
    let mut small_preproc = SecureSmallPreprocessing::default()
        .execute(&mut session, batch)
        .await
        .map_err(|e| anyhow::anyhow!("secure offline phase failed: {e:?}"))?;

    // CANARY A (divergence bisection, H2): open one spare random in the SYNC
    // session. If this digest differs across nodes, the divergence is already
    // present in the PRSS/offline material; if it agrees, the offline output
    // is consistent and the fault is later.
    {
        let canary_share = RandomPreprocessing::<Poly>::next_random_vec(&mut small_preproc, 1)
            .map_err(|e| anyhow::anyhow!("canary A draw: {e:?}"))?
            .pop()
            .context("canary A: empty draw")?;
        let opened = SecureRobustOpen::default()
            .robust_open_to_all(
                &session,
                canary_share.value(),
                cfg.committee.session_threshold(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("canary A open: {e:?}"))?
            .context("canary A: no reconstruction")?;
        eprintln!(
            "celar-kms-node[{}]: CANARY-A (sync/offline) {}",
            cfg.role,
            &sha256_hex(format!("{opened:?}").as_bytes())[..16],
        );
    }

    let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();
    dkg_preproc
        .fill_from_base_preproc(
            params_dkg,
            keyset_config,
            session.get_mut_base_session(),
            &mut small_preproc,
        )
        .await
        .map_err(|e| anyhow::anyhow!("filling DKG preprocessing failed: {e:?}"))?;

    // ONLINE KEYGEN — a fresh ASYNC session, exactly like upstream production
    // (H2 root cause, 2026-08-17): the reconstruction function is selected by
    // network mode (open.rs). Sync uses reconstruct_w_errors_sync, which
    // reconstructs from whatever share subset beat the round deadline and
    // error-corrects stragglers away — over a real network different parties
    // see different subsets and derive DIFFERENT pk_G with empty corrupt sets
    // (observed thrice, split along a contiguous role boundary). Async uses
    // the stricter consistency-checked reconstruction and effectively no
    // deadline. Production runs Sync only for PRSS/broadcast/preprocessing
    // and the online DKG in Async with a separate derived session id.
    let sid_online = SessionId::from(cfg.session_id as u128 + 1);
    let networking_online = manager
        .make_network_session(sid_online, &assignment, my_role, NetworkMode::Async)
        .await
        .context("creating the online (async) network session")?;
    let params_online = SessionParameters::new(
        cfg.committee.session_threshold() as u8,
        sid_online,
        my_role,
        role_set.clone(),
    )
    .map_err(|e| anyhow::anyhow!("online session parameters: {e:?}"))?;
    let base_online = BaseSession::new(params_online, networking_online, AesRng::from_random_seed())
        .map_err(|e| anyhow::anyhow!("online base session: {e:?}"))?;
    let prss_state_online = prss_setup.new_prss_session_state(sid_online);
    let mut online = SmallSession::<Poly>::new_from_prss_state(base_online, prss_state_online)
        .map_err(|e| anyhow::anyhow!("online small session: {e:?}"))?;

    // CANARY B: open a second spare random over the ASYNC session. Agreement
    // here (with CANARY A agreeing too) pins any pk split on fill/keygen;
    // disagreement here with A agreeing pins it on the async session wiring
    // (PRSS state re-derivation or session identity).
    {
        let canary_share = RandomPreprocessing::<Poly>::next_random_vec(&mut small_preproc, 1)
            .map_err(|e| anyhow::anyhow!("canary B draw: {e:?}"))?
            .pop()
            .context("canary B: empty draw")?;
        let opened = SecureRobustOpen::default()
            .robust_open_to_all(
                &online,
                canary_share.value(),
                cfg.committee.session_threshold(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("canary B open: {e:?}"))?
            .context("canary B: no reconstruction")?;
        eprintln!(
            "celar-kms-node[{}]: CANARY-B (async/pre-keygen) {}",
            cfg.role,
            &sha256_hex(format!("{opened:?}").as_bytes())[..16],
        );
    }

    eprintln!("celar-kms-node[{}]: distributed keygen (async session)…", cfg.role);
    let mut tag = tfhe::Tag::default();
    tag.set_data(cfg.committee.tag.as_bytes());
    // COMPRESSED keygen (H2 root cause #2, 2026-08-17): the ceremony commits
    // to the COMPRESSED (integer-domain, XOF-seeded) keyset — a deterministic
    // function of the agreed seed + MPC-opened values, bit-identical across
    // parties. The full ServerKey stores bootstrapping keys in the FOURIER
    // domain (f64), and that local integer→float conversion is not
    // bit-reproducible even across processes on one machine (tfhe-fft
    // runtime dispatch / A3 finding) — committing to the decompressed form
    // made honest parties' pk_G digests differ while every opened value
    // agreed. Decompression is a LOCAL operation, done per node at use time.
    // This also matches upstream production, which stores compressed keysets.
    let (compressed_pk, sk) = SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::compressed_keygen(
        &mut online,
        dkg_preproc.as_mut(),
        params_dkg,
        tag,
    )
    .await
    .map_err(|e| anyhow::anyhow!("distributed keygen failed: {e:?}"))?;

    // Evidence over vibes: if the robust layers disqualified anyone, each
    // party's local corrupt-set says WHO and explains pk_G splits at collect
    // (a party that the other n−1 excluded derives a different key than
    // they do, while still "completing" locally). Checked on BOTH sessions.
    let mut corrupt = session.get_mut_base_session().corrupt_roles().clone();
    corrupt.extend(online.get_mut_base_session().corrupt_roles().iter().cloned());
    if corrupt.is_empty() {
        eprintln!("celar-kms-node[{}]: corrupt set EMPTY — clean run", cfg.role);
    } else {
        eprintln!(
            "celar-kms-node[{}]: ⚠ corrupt set NOT empty: {:?} — this run's \
             pk_G will disagree across parties; abort and retry the ceremony",
            cfg.role, corrupt
        );
    }

    let wall_secs = started.elapsed().as_secs_f64();

    // 6) fragment + optional dev key material. pk_G identity = digest of the
    // COMPRESSED keyset (see the compressed_keygen comment above).
    let pk_bytes = bincode::serialize(&compressed_pk).context("serializing compressed pk_G")?;
    let sk_bytes = bincode::serialize(&sk).context("serializing share vector")?;
    let fragment = TranscriptFragment {
        schema: FRAGMENT_SCHEMA.to_string(),
        role: cfg.role,
        committee_parties: cfg.committee.parties,
        session_id: cfg.session_id,
        params: cfg.committee.params.name().to_string(),
        tag: cfg.committee.tag.clone(),
        pk_g_sha256: sha256_hex(&pk_bytes),
        share_commitment_sha256: sha256_hex(&sk_bytes),
        wall_secs,
        transport: "grpc-mtls".to_string(),
        roster_sha256,
    };
    fs::write(
        cfg.out_dir.join(fragment_file(cfg.role)),
        serde_json::to_string_pretty(&fragment)?,
    )?;
    if cfg.write_dev_keys {
        fs::write(cfg.out_dir.join(crate::transcript::share_file(cfg.role)), &sk_bytes)?;
        if cfg.role == 1 {
            fs::write(cfg.out_dir.join(crate::transcript::PK_FILE), &pk_bytes)?;
        }
        // Per-role pk dump (H2 bisection): lets `cmp -l` locate the first
        // divergent byte offset between two nodes' pk serializations.
        fs::write(
            cfg.out_dir.join(format!("pk_g_{:03}.bin", cfg.role)),
            &pk_bytes,
        )?;
        fs::write(
            cfg.out_dir.join("DEV-KEYS-WARNING.txt"),
            "Key material written by a DEV ceremony run for transcript\n\
             re-verification. A real ceremony never persists shares unprotected.\n",
        )?;
    }

    server_handle.abort(); // ceremony done; this daemon's one job is complete
    Ok(fragment)
}
