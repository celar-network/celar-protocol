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
//! This is deliberately the seed of the real Celar KMS daemon: threshold
//! decryption and re-encryption add
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
use threshold_execution::large_execution::offline::SecureLargePreprocessing;
use threshold_execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use threshold_execution::online::preprocessing::{create_memory_factory, DKGPreprocessing};
use threshold_execution::runtime::sessions::large_session::LargeSession;
use threshold_execution::runtime::sessions::base_session::{
    BaseSession, GenericBaseSessionHandles, ToBaseSession,
};
use threshold_execution::runtime::sessions::small_session::SmallSession;
use threshold_execution::runtime::sessions::session_parameters::SessionParameters;
use threshold_execution::online::preprocessing::RandomPreprocessing;
use threshold_execution::online::preprocessing::TriplePreprocessing;
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

use algebra::base_ring::Z64;
use threshold_execution::endpoints::reshare_sk::{
    ResharePreprocRequired, ReshareSecretKeys, SecureReshareSecretKeys,
};
use threshold_execution::online::preprocessing::dummy::DummyPreprocessing;
use threshold_execution::runtime::sessions::base_session::GenericBaseSession;
use threshold_execution::runtime::sessions::session_parameters::GenericSessionParameters;
use threshold_types::role::{DualRole, TwoSetsRole, TwoSetsThreshold};

use crate::config::CommitteeConfig;
use crate::transcript::{sha256_hex, share_file};
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
    /// Path to the vetted committee roster governing this ceremony.
    /// When set, the node validates the roster (§7.7 rules for genesis mode),
    /// checks its OWN entry and every peer against it, verifies the TLS
    /// trust-root set matches the roster's CA pins exactly, and stamps the
    /// roster digest into its transcript fragment.
    #[serde(default)]
    pub roster: Option<PathBuf>,
    /// Path to this seat's ed25519 OPERATIONAL signing key (the private half of
    /// its roster-registered `signing_pubkey`, as emitted by `celar-certs`).
    /// When set, the node signs its transcript endorsement digest so the
    /// fragment carries a quorum-checkable seat endorsement. Absent = the
    /// fragment is written unsigned (dev).
    #[serde(default)]
    pub signing_key: Option<PathBuf>,
    /// Core-to-core transport tuning. Absent = committee-scale defaults (see
    /// `committee_net_config`). The upstream transport defaults are calibrated
    /// for a 5-party committee; at larger sizes over a long offline phase,
    /// seats drift apart under load and the default buffers/retry-windows drop
    /// the laggard's messages. A dropped message in a reliable-broadcast round
    /// is indistinguishable from the sender equivocating, so the (honest)
    /// sender is permanently evicted from the committee — which shrinks the
    /// honest pool and cascades to collapse. This block widens every knob on
    /// that drop path; it is serialised so operators can re-tune per run
    /// without rebuilding.
    #[serde(default)]
    pub net: Option<threshold_networking::grpc::CoreToCoreNetworkConfig>,
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

/// Core-to-core transport tuning for committee-scale ceremonies. The upstream
/// defaults are sized for 5 parties (their timeouts are annotated "tested for
/// (5,1)"); at genesis scale, seats on busier hosts fall behind over the long
/// offline phase and these default limits silently drop their messages, which
/// the reliable broadcast then reads as corruption and evicts the honest
/// party — cascading to a whole-session abort. Every value here sits on that
/// drop path and is widened with headroom (buffers ~30-60x, retry/enqueue
/// windows to 10 min) while staying bounded so a peer cannot force unbounded
/// memory. Used whenever the node config omits an explicit `net` block.
fn committee_net_config() -> threshold_networking::grpc::CoreToCoreNetworkConfig {
    threshold_networking::grpc::CoreToCoreNetworkConfig {
        // Incoming per-peer queue depth (default 70): 29 peers can burst while
        // a seat is mid-compute; a shallow queue overflows and drops.
        message_limit: Some(2048),
        // Retry budget before a failing send is abandoned (default 60s).
        max_elapsed_time: Some(600),
        // How long a send waits to enqueue before dropping (default 60s).
        max_waiting_time_for_message_queue: Some(600),
        // Default per-round receive wait (we also set 600s per round explicitly).
        network_timeout: Some(600),
        // Look-ahead for a peer ahead of us, and the hard cap on buffered
        // future messages (default 32): both must exceed the round-drift that
        // develops across hosts of differing seat counts.
        max_future_rounds: Some(2048),
        max_buffered_future_msgs: Some(2048),
        ..Default::default()
    }
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

    /// The core-to-core transport tuning to run under: the config's explicit
    /// `net` block if present, else the committee-scale defaults.
    fn net_config(&self) -> threshold_networking::grpc::CoreToCoreNetworkConfig {
        self.net.unwrap_or_else(committee_net_config)
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
    /// Digest of the roster this node ran under (None = dev, rosterless).
    #[serde(default)]
    pub roster_sha256: Option<String>,
    /// This seat's ed25519 signature (hex) over `endorsement_digest()`, made
    /// with the operational key its roster entry registered. It supplies the
    /// AUTHORSHIP a bare hash chain cannot: a submission carrying
    /// reconstruction-quorum-many valid endorsements proves the rostered
    /// committee endorsed this transcript. None = the seat had no signing key
    /// configured (unsigned dev fragment).
    #[serde(default)]
    pub endorsement: Option<String>,
}

/// Domain separator for the endorsement digest. Bump only if the signed field
/// set changes — a signature is over the digest, and the digest over these.
pub const ENDORSEMENT_DOMAIN: &str = "celar-transcript-endorsement/v1";

impl TranscriptFragment {
    /// The canonical digest every honest seat computes IDENTICALLY and signs.
    /// It covers only the COMMON epoch fields — committee size, session, params,
    /// tag, pk_G, roster — and deliberately excludes the per-seat share
    /// commitment, wall time, transport, and the signature itself, so a quorum
    /// of signatures is over one shared value. Serialised as a JSON tuple so
    /// the `tag` field cannot inject a delimiter.
    ///
    /// This is the INTERFACE the on-chain write path must mirror to verify
    /// these signatures — keep the two definitions in lockstep.
    pub fn endorsement_digest(&self) -> String {
        let canonical = serde_json::to_string(&(
            ENDORSEMENT_DOMAIN,
            self.committee_parties,
            self.session_id,
            self.params.as_str(),
            self.tag.as_str(),
            self.pk_g_sha256.as_str(),
            self.roster_sha256.as_deref(),
        ))
        .expect("tuple of primitives always serializes");
        sha256_hex(canonical.as_bytes())
    }
}

pub const FRAGMENT_SCHEMA: &str = "celar-dkg-fragment/v1";

pub fn fragment_file(role: usize) -> String {
    format!("fragment_{role:03}.json")
}

/// Sign an endorsement digest (hex) with the seat's ed25519 operational key
/// (a 64-hex file, as `celar-certs` writes). Returns the signature as 128-hex.
/// The signed message is the digest's hex bytes; the verifier recomputes the
/// same digest and checks the signature against the roster's registered key.
fn sign_endorsement(key_path: &Path, digest_hex: &str) -> Result<String> {
    use ed25519_dalek::{Signer, SigningKey};
    let raw = fs::read_to_string(key_path)
        .with_context(|| format!("reading operational signing key {}", key_path.display()))?;
    let bytes = hex::decode(raw.trim()).context("operational signing key is not hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("operational signing key is not 32 bytes"))?;
    let sk = SigningKey::from_bytes(&arr);
    Ok(hex::encode(sk.sign(digest_hex.as_bytes()).to_bytes()))
}

/// Domain-separated input for the per-seat contribution-seed VRF (SR9 item 5).
pub const VRF_CONTRIBUTION_DOMAIN: &str = "celar.kms.vrf.contribution.v1";

fn vrf_contribution_msg(epoch: u64, index: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(VRF_CONTRIBUTION_DOMAIN.len() + 16);
    msg.extend_from_slice(VRF_CONTRIBUTION_DOMAIN.as_bytes());
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&index.to_be_bytes());
    msg
}

/// This seat's VRF output over `(epoch, index)` — a domain-separated
/// deterministic ed25519 signature under the seat's operational key (the same
/// key `sign_endorsement` uses; no new key or roster field). Fed to
/// `mask_supply::vrf_mixed_contribution_seed`, so a fleet-wide local-RNG failure
/// degrades to "predictable to the seat" rather than "to the coalition"
/// (SR9 adopt-list item 5). Verifiable by the seat's rostered pubkey — see
/// `verify_vrf_contribution`. v1 reuses ed25519-sign-as-VRF: adequate for the
/// entropy purpose, not a strict RFC-9381 ECVRF
/// (design: `doc/engg/tasks/vrf-contribution-seeds/design.md`).
pub fn vrf_contribution_output(key_path: &Path, epoch: u64, index: u64) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};
    let raw = fs::read_to_string(key_path)
        .with_context(|| format!("reading operational signing key {}", key_path.display()))?;
    let bytes = hex::decode(raw.trim()).context("operational signing key is not hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("operational signing key is not 32 bytes"))?;
    let sk = SigningKey::from_bytes(&arr);
    Ok(sk.sign(&vrf_contribution_msg(epoch, index)).to_bytes().to_vec())
}

/// Verify a seat's VRF output against its rostered ed25519 pubkey (64-hex) —
/// the "verifiable" half: an auditor confirms the seat used its registered key
/// over `(epoch, index)`, so the contribution seed provably mixes that key.
pub fn verify_vrf_contribution(
    pubkey_hex: &str,
    epoch: u64,
    index: u64,
    vrf_output: &[u8],
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = hex::decode(pubkey_hex.trim())
        .context("vrf pubkey is not hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("vrf pubkey is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).context("vrf pubkey is not a valid ed25519 point")?;
    let sig_bytes: [u8; 64] = vrf_output
        .try_into()
        .map_err(|_| anyhow::anyhow!("vrf output is not a 64-byte ed25519 signature"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&vrf_contribution_msg(epoch, index), &sig)
        .map_err(|e| anyhow::anyhow!("vrf output failed verification: {e}"))
}

/// Verify that a set of transcript fragments carries a **reconstruction quorum**
/// of valid seat endorsements over ONE transcript — the authorship check a
/// bare hash chain cannot supply (structural checks constrain the bytes; this
/// checks who signed them). Returns the count of distinct valid signers.
///
/// It authenticates that the rostered committee's quorum ENDORSES this
/// transcript — not that the ceremony inside it was honest (a colluding quorum
/// can still sign a fabricated transcript). That is the trust the §7.7
/// committee model already carries; it adds no new assumption. This is the
/// reference verifier; the on-chain write path must mirror it.
pub fn verify_quorum_endorsement(
    fragments: &[TranscriptFragment],
    roster: &crate::committee::CommitteeRoster,
) -> Result<usize> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if fragments.is_empty() {
        bail!("no fragments to verify");
    }
    // Every fragment must endorse the SAME transcript, else they are not one
    // committee endorsing one epoch.
    let digest = fragments[0].endorsement_digest();
    for f in fragments {
        if f.endorsement_digest() != digest {
            bail!(
                "fragment for role {} endorses a different transcript — the \
                 fragments do not agree on one transcript",
                f.role
            );
        }
    }
    let msg = digest.as_bytes();

    let mut valid_signers = std::collections::HashSet::new();
    for f in fragments {
        let Some(sig_hex) = &f.endorsement else {
            continue; // unsigned fragment contributes no authorship
        };
        let Some(member) = roster.members.iter().find(|m| m.role == f.role) else {
            bail!("fragment role {} is not a member of the roster", f.role);
        };
        // A key or signature that does not parse is simply not a valid
        // endorsement — skip it rather than counting or erroring.
        let vk = hex::decode(&member.signing_pubkey)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .and_then(|a| VerifyingKey::from_bytes(&a).ok());
        let sig = hex::decode(sig_hex)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
            .map(|a| Signature::from_bytes(&a));
        if let (Some(vk), Some(sig)) = (vk, sig) {
            if vk.verify(msg, &sig).is_ok() {
                valid_signers.insert(f.role);
            }
        }
    }

    let quorum = roster.reconstruction_quorum();
    let n = valid_signers.len();
    if n < quorum {
        bail!(
            "transcript carries only {n} valid seat endorsement(s); the roster's \
             reconstruction quorum is {quorum}. The transcript is NOT authenticated \
             by the committee — structure may check out but authorship does not."
        );
    }
    Ok(n)
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

    // Enforce the vetted roster before any networking happens.
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
        cfg.net_config(),
    )?);
    let mpc_service = manager.new_server(TlsExtensionGetter::TlsConnectInfo);

    let bind = format!("{}:{}", cfg.listen_addr, cfg.my_peer().port);
    let server_tls_cfg = server_tls(&cfg.tls)?;
    let server_handle = tokio::spawn(
        Server::builder()
            .tls_config(server_tls_cfg)?
            .http2_adaptive_window(Some(true))
            // Match the client-side keepalive: ping idle peer connections and
            // keep the TCP flow alive so a quiet stretch during the offline
            // phase does not get the connection reaped (a reaped connection then
            // fails to re-establish and the peer is wrongly evicted, which at
            // genesis threshold has no margin and cascades to a whole-session abort).
            .http2_keepalive_interval(Some(Duration::from_secs(20)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .tcp_keepalive(Some(Duration::from_secs(20)))
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

    let (compressed_pk, sk) = if cfg.committee.preprocessing
        == crate::config::PreprocMode::SecureLarge
    {
        // ---- SECURE-LARGE offline (genesis-capable). No PRSS: the large-
        // session VSS machinery provides the randomness, and PRSS is
        // structurally refused at genesis size (the set-count correctness
        // cap). Same Sync-offline → Async-keygen split as the PRSS path;
        // chunked batches per the simulator's batch-ceiling finding.
        let mut large = LargeSession::new(base);
        let params_dkg = match cfg.committee.params {
            crate::config::ParamsChoice::Test => {
                threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS
            }
            crate::config::ParamsChoice::NistP32SnsFglwe => {
                threshold_execution::tfhe_internals::parameters::NIST_PARAMS_P32_SNS_FGLWE
            }
        };
        let keyset_config = KeySetConfig::default();
        // +1 spare random: the divergence canary, opened in the sync session.
        let batch = BatchParams {
            triples: params_dkg.total_triples_required(keyset_config),
            randoms: params_dkg.total_randomness_required(keyset_config) + 1,
        };
        let chunk = cfg.committee.preproc_chunk.max(1);
        eprintln!(
            "celar-kms-node[{}]: secure-LARGE offline phase ({} triples, {} randoms, chunk {})…",
            cfg.role, batch.triples, batch.randoms, chunk
        );
        let mut large_preproc = InMemoryBasePreprocessing::<Poly>::default();
        let mut left = batch;
        while left.triples > 0 || left.randoms > 0 {
            large
                .network()
                .set_timeout_for_next_round(Duration::from_secs(cfg.round_timeout_secs))
                .await;
            let step = BatchParams {
                triples: left.triples.min(chunk),
                randoms: left.randoms.min(chunk),
            };
            let mut chunk_out = SecureLargePreprocessing::default()
                .execute(&mut large, step)
                .await
                .map_err(|e| anyhow::anyhow!("secure large offline phase failed: {e:?}"))?;
            large_preproc.append_triples(
                chunk_out
                    .next_triple_vec(step.triples)
                    .map_err(|e| anyhow::anyhow!("draining chunk triples: {e:?}"))?,
            );
            large_preproc.append_randoms(
                chunk_out
                    .next_random_vec(step.randoms)
                    .map_err(|e| anyhow::anyhow!("draining chunk randoms: {e:?}"))?,
            );
            left.triples -= step.triples;
            left.randoms -= step.randoms;
        }

        // CANARY (sync/offline) — same divergence bisection as the PRSS path.
        {
            let canary_share =
                RandomPreprocessing::<Poly>::next_random_vec(&mut large_preproc, 1)
                    .map_err(|e| anyhow::anyhow!("canary draw: {e:?}"))?
                    .pop()
                    .context("canary: empty draw")?;
            let opened = SecureRobustOpen::default()
                .robust_open_to_all(
                    &large,
                    canary_share.value(),
                    cfg.committee.session_threshold(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("canary open: {e:?}"))?
                .context("canary: no reconstruction")?;
            eprintln!(
                "celar-kms-node[{}]: CANARY-A (sync/offline, large) {}",
                cfg.role,
                &sha256_hex(format!("{opened:?}").as_bytes())[..16],
            );
        }

        let mut dkg_preproc = create_memory_factory().create_dkg_preprocessing_with_sns();
        dkg_preproc
            .fill_from_base_preproc(
                params_dkg,
                keyset_config,
                large.get_mut_base_session(),
                &mut large_preproc,
            )
            .await
            .map_err(|e| anyhow::anyhow!("filling DKG preprocessing failed: {e:?}"))?;

        // ONLINE KEYGEN — fresh ASYNC session (same H2 doctrine as the PRSS
        // path; see that arm's comment). Plain BaseSession: no PRSS state
        // exists or is needed on the large path.
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
        let mut base_online =
            BaseSession::new(params_online, networking_online, AesRng::from_random_seed())
                .map_err(|e| anyhow::anyhow!("online base session: {e:?}"))?;

        eprintln!(
            "celar-kms-node[{}]: distributed keygen (async session, large path)…",
            cfg.role
        );
        let mut tag = tfhe::Tag::default();
        tag.set_data(cfg.committee.tag.as_bytes());
        let (compressed_pk, sk) =
            SecureOnlineDistributedKeyGen128::<EXTENSION_DEGREE>::compressed_keygen(
                &mut base_online,
                dkg_preproc.as_mut(),
                params_dkg,
                tag,
            )
            .await
            .map_err(|e| anyhow::anyhow!("distributed keygen failed: {e:?}"))?;

        let mut corrupt = large.get_mut_base_session().corrupt_roles().clone();
        corrupt.extend(base_online.corrupt_roles().iter().cloned());
        if corrupt.is_empty() {
            eprintln!("celar-kms-node[{}]: corrupt set EMPTY — clean run", cfg.role);
        } else {
            eprintln!(
                "celar-kms-node[{}]: ⚠ corrupt set NOT empty: {:?} — this run's \
                 pk_G will disagree across parties; abort and retry the ceremony",
                cfg.role, corrupt
            );
        }
        (compressed_pk, sk)
    } else {

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
    // runtime dispatch finding) — committing to the decompressed form
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

        (compressed_pk, sk)
    };

    let wall_secs = started.elapsed().as_secs_f64();

    // 6) fragment + optional dev key material. pk_G identity = digest of the
    // COMPRESSED keyset (see the compressed_keygen comment above).
    let pk_bytes = bincode::serialize(&compressed_pk).context("serializing compressed pk_G")?;
    let sk_bytes = bincode::serialize(&sk).context("serializing share vector")?;
    let mut fragment = TranscriptFragment {
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
        endorsement: None,
    };
    // Endorse: sign the canonical transcript digest with this seat's
    // operational key so the archived epoch carries a quorum-checkable
    // authorship signal.
    match &cfg.signing_key {
        Some(key_path) => {
            let digest = fragment.endorsement_digest();
            fragment.endorsement = Some(sign_endorsement(key_path, &digest)?);
            eprintln!("celar-kms-node[{}]: transcript endorsement signed", cfg.role);
        }
        None => eprintln!(
            "celar-kms-node[{}]: ⚠ no operational signing key — fragment is UNSIGNED",
            cfg.role
        ),
    }
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

    // Announce completion BEFORE blocking: the fragment is written and this
    // seat holds its share. This line is the collectable success signal.
    println!(
        "CEREMONY-OK role={} wall={:.1}s pk_G {} fragment {}",
        fragment.role,
        fragment.wall_secs,
        fragment.pk_g_sha256,
        cfg.out_dir.join(fragment_file(fragment.role)).display(),
    );
    // Do NOT exit yet. The online keygen needs every peer reachable until the
    // LAST seat finishes; a seat that aborts its server the instant it
    // completes drops connections that slower peers still need, and at
    // committee scale that cascades — fast finishers leave, laggards get
    // connection-refused on their final-round sends and never complete. Keep
    // serving until the operator stops this process, which should be only
    // after all fragments have been collected.
    eprintln!(
        "celar-kms-node[{}]: fragment written; STAYING UP to serve peers — \
         stop this process only after all fragments are collected.",
        cfg.role
    );
    let _ = server_handle.await;
    Ok(fragment)
}

// ---------------------------------------------------------------- distributed decrypt

/// Bring up this seat's mTLS transport and one networked `BaseSession` at
/// `mode`/`threshold`. Factored out of the ceremony's inline setup so the
/// distributed decrypt reuses exactly the same transport + identity plumbing
/// (the `MpcIdentity` keying, the committee-scale net tuning, the keepalives).
/// Returns the manager, the still-running server task (keep it alive until the
/// operator stops), and the base session.
async fn bring_up_session(
    cfg: &NodeConfig,
    sid: SessionId,
    threshold: u8,
    mode: NetworkMode,
) -> Result<(
    Arc<GrpcNetworkingManager>,
    tokio::task::JoinHandle<std::result::Result<(), tonic::transport::Error>>,
    BaseSession,
)> {
    let my_role = Role::indexed_from_one(cfg.role);
    let client_tls = build_client_tls(&cfg.tls)?;
    let manager = Arc::new(GrpcNetworkingManager::new(Some(client_tls), cfg.net_config())?);
    let mpc_service = manager.new_server(TlsExtensionGetter::TlsConnectInfo);

    let bind = format!("{}:{}", cfg.listen_addr, cfg.my_peer().port);
    let server_tls_cfg = server_tls(&cfg.tls)?;
    let server_handle = tokio::spawn(
        Server::builder()
            .tls_config(server_tls_cfg)?
            .http2_adaptive_window(Some(true))
            .http2_keepalive_interval(Some(Duration::from_secs(20)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .tcp_keepalive(Some(Duration::from_secs(20)))
            .add_service(mpc_service)
            .serve(bind.parse().context("parsing bind address")?),
    );
    eprintln!("celar-kms-node[{}]: mTLS MPC server on {bind}", cfg.role);

    tokio::time::sleep(Duration::from_secs(cfg.startup_wait_secs)).await;

    let assignment: RoleAssignment<Role> = HashMap::from_iter(cfg.peers.iter().map(|p| {
        (
            Role::indexed_from_one(p.role),
            Identity::new(
                p.host.clone(),
                p.port,
                Some(p.mpc.clone().unwrap_or_else(|| p.host.clone())),
            ),
        )
    }))
    .into();
    let role_set: std::collections::HashSet<Role> = assignment.keys().cloned().collect();

    let networking = manager
        .make_network_session(sid, &assignment, my_role, mode)
        .await
        .context("creating the network session (are all peers reachable?)")?;
    let params = SessionParameters::new(threshold, sid, my_role, role_set)
        .map_err(|e| anyhow::anyhow!("session parameters: {e:?}"))?;
    let base = BaseSession::new(params, networking, AesRng::from_random_seed())
        .map_err(|e| anyhow::anyhow!("base session: {e:?}"))?;

    Ok((manager, server_handle, base))
}

/// What one seat reports from a distributed decrypt: the recovered plaintext,
/// so the operator can confirm all seats agree (the analogue of pk_G equality).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResultFragment {
    pub schema: String,
    pub role: usize,
    pub parties: usize,
    pub degree: usize,
    pub committee_threshold: usize,
    pub recovered: u64,
    pub value_expected: u64,
    pub agree: bool,
    pub wall_secs: f64,
}

pub const DECRYPT_RESULT_SCHEMA: &str = "celar-decrypt-result/v1";

pub fn decrypt_result_file(role: usize) -> String {
    format!("decrypt_result_{role:03}.json")
}

/// Run this seat's side of a DISTRIBUTED degree-decoupled threshold decrypt over
/// mTLS. The committee shape and the artifacts come from `inputs_dir` (produced
/// by `celar-dkg decrypt-prepare`): the shared SnS ciphertext, this seat's
/// degree-`d` key share and flooding-mask shares. Reconstruction happens at the
/// KEY's degree via the network robust-open, so the session runs at the RS
/// tolerance `⌊(n−degree−1)/2⌋` (from the manifest), decoupled from the degree.
pub async fn run_distributed_decrypt(
    cfg: &NodeConfig,
    inputs_dir: &Path,
) -> Result<DecryptResultFragment> {
    use algebra::sharing::share::Share;
    use threshold_execution::endpoints::decryption::{
        SnsDecryptionKeyType, SnsRadixOrBoolCiphertext,
    };
    use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;

    cfg.validate()?;
    let manifest: crate::decrypt::DecoupledDecryptManifest = serde_json::from_str(
        &fs::read_to_string(inputs_dir.join(crate::decrypt::DECOUPLED_MANIFEST_FILE))
            .context("reading decrypt-inputs.json")?,
    )?;
    if manifest.parties != cfg.committee.parties {
        bail!(
            "inputs are for a {}-seat committee but this node's committee is {}",
            manifest.parties,
            cfg.committee.parties
        );
    }
    let degree = manifest.degree;
    let threshold = manifest.committee_threshold;

    // This seat's degree-d key share and its per-block flooding-mask shares.
    let share: PrivateKeySet<EXTENSION_DEGREE> = bincode::deserialize(
        &fs::read(inputs_dir.join(crate::transcript::share_file(cfg.role)))
            .context("reading this seat's degree-d share")?,
    )?;
    let mask_shares: Vec<Share<Poly>> = bincode::deserialize(
        &fs::read(inputs_dir.join(crate::decrypt::decoupled_mask_file(cfg.role)))
            .context("reading this seat's mask shares")?,
    )?;
    // The shared switch-and-squash ciphertext — identical across seats. The
    // wrapper enum is not Serialize; the producer wrote the inner tfhe
    // SquashedNoiseRadixCiphertext, so reconstruct the Radix wrapper here.
    let inner: tfhe::integer::ciphertext::SquashedNoiseRadixCiphertext = bincode::deserialize(
        &fs::read(inputs_dir.join(crate::decrypt::DECOUPLED_CT_FILE))
            .context("reading the shared SnS ciphertext")?,
    )?;
    let large_ct = SnsRadixOrBoolCiphertext::Radix(inner);

    // Networked SYNC session at the RS tolerance. The decrypt is a SINGLE
    // robust-open (not keygen's many-round opens under tight deadlines, which is
    // what the Async doctrine exists for), so with a generous per-round timeout
    // every seat collects all shares and reconstructs identically — matching the
    // in-process test, which runs this same open in Sync. Async here has
    // effectively no deadline and would wait forever. Wrap as a LargeSession —
    // it satisfies BaseSessionHandles for the robust-open and needs no PRSS.
    let sid = SessionId::from(cfg.session_id as u128);
    let (_manager, server_handle, base) =
        bring_up_session(cfg, sid, threshold as u8, NetworkMode::Sync).await?;
    base.network()
        .set_timeout_for_next_round(Duration::from_secs(cfg.round_timeout_secs))
        .await;
    let large = LargeSession::new(base);

    eprintln!(
        "celar-kms-node[{}]: degree-aware decrypt (degree {degree}, committee t={threshold}, sync)…",
        cfg.role
    );
    let started = Instant::now();
    let recovered = crate::degree_decrypt::run_degree_aware_decrypt(
        &large,
        &share,
        &mask_shares,
        &large_ct,
        degree,
        SnsDecryptionKeyType::SnsKey,
    )
    .await
    .map_err(|e| anyhow::anyhow!("degree-aware decrypt failed: {e:?}"))?;
    let wall_secs = started.elapsed().as_secs_f64();

    let agree = recovered == manifest.value_expected;
    let fragment = DecryptResultFragment {
        schema: DECRYPT_RESULT_SCHEMA.to_string(),
        role: cfg.role,
        parties: manifest.parties,
        degree,
        committee_threshold: threshold,
        recovered,
        value_expected: manifest.value_expected,
        agree,
        wall_secs,
    };
    fs::create_dir_all(&cfg.out_dir)?;
    fs::write(
        cfg.out_dir.join(decrypt_result_file(cfg.role)),
        serde_json::to_string_pretty(&fragment)?,
    )?;
    println!(
        "DECRYPT-OK role={} recovered={} expected={} {} wall={:.2}s result {}",
        cfg.role,
        recovered,
        manifest.value_expected,
        if agree { "AGREE" } else { "⚠ MISMATCH" },
        wall_secs,
        cfg.out_dir.join(decrypt_result_file(cfg.role)).display(),
    );
    eprintln!(
        "celar-kms-node[{}]: result written; STAYING UP to serve peers — \
         stop this process only after all seats have finished.",
        cfg.role
    );
    let _ = server_handle.await;
    Ok(fragment)
}

// ---------------------------------------------------------------- distributed reshare

/// One seat's distributed upward-reshare result — the new degree-`d` share's
/// digest, so the operator can confirm every seat reshared one consistent key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareResultFragment {
    pub schema: String,
    pub role: usize,
    pub parties: usize,
    pub old_degree: usize,
    pub new_degree: usize,
    pub new_share_sha256: String,
    pub wall_secs: f64,
}

pub const RESHARE_RESULT_SCHEMA: &str = "celar-reshare-result/v1";

pub fn reshare_result_file(role: usize) -> String {
    format!("reshare_result_{role:03}.json")
}

/// Run this seat's side of a DISTRIBUTED upward reshare over mTLS — an in-place
/// degree raise on the committee (old committee = new committee = the peers,
/// every seat playing `TwoSetsRole::Both`), taking the key's sharing degree from
/// the committee's current degree up to `new_degree`. pk_G is invariant (§7.5).
/// Reads this seat's old share from `in_dir`, writes its new degree-`new_degree`
/// share to `out_dir`.
///
/// Unlike the single-process `run_upward_reshare` (test harness, all shares in
/// one process), the resharing runs over the real network so no party ever sees
/// another's share — the production requirement for a genesis→decoupled-degree
/// transition. Two sessions are multiplexed on one mTLS transport: a combined
/// `TwoSetsRole`-keyed session (the cross-set channel) and the set-2 `Role`
/// session (the new committee's channel).
pub async fn run_distributed_reshare(
    cfg: &NodeConfig,
    in_dir: &Path,
    out_dir: &Path,
    new_degree: usize,
) -> Result<ReshareResultFragment> {
    use threshold_execution::tfhe_internals::private_keysets::PrivateKeySet;

    cfg.validate()?;
    let n = cfg.committee.parties;
    // Old sharing degree = the committee's session threshold — the same
    // derivation the single-process upward reshare uses.
    let old_degree = CommitteeConfig {
        parties: n,
        ..Default::default()
    }
    .session_threshold();
    if new_degree <= old_degree {
        bail!("new degree {new_degree} must exceed the old degree {old_degree}");
    }
    if n < new_degree + 1 {
        bail!("committee of {n} cannot carry a degree-{new_degree} sharing (need >= degree+1)");
    }
    let params = match cfg.committee.params {
        crate::config::ParamsChoice::Test => {
            threshold_execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS
        }
        crate::config::ParamsChoice::NistP32SnsFglwe => {
            threshold_execution::tfhe_internals::parameters::NIST_PARAMS_P32_SNS_FGLWE
        }
    };

    // This seat's old degree-`t` share — the set-1 input.
    let mut my_share: PrivateKeySet<EXTENSION_DEGREE> = bincode::deserialize(
        &fs::read(in_dir.join(share_file(cfg.role))).context("reading this seat's old share")?,
    )?;
    let oprf = my_share.oprf_secret_key_share.is_some();

    // --- mTLS transport: one server, two sessions multiplexed by session id ---
    let my_r = Role::indexed_from_one(cfg.role);
    let client_tls = build_client_tls(&cfg.tls)?;
    let manager = Arc::new(GrpcNetworkingManager::new(Some(client_tls), cfg.net_config())?);
    let mpc_service = manager.new_server(TlsExtensionGetter::TlsConnectInfo);
    let bind = format!("{}:{}", cfg.listen_addr, cfg.my_peer().port);
    let server_tls_cfg = server_tls(&cfg.tls)?;
    let server_handle = tokio::spawn(
        Server::builder()
            .tls_config(server_tls_cfg)?
            .http2_adaptive_window(Some(true))
            .http2_keepalive_interval(Some(Duration::from_secs(20)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .tcp_keepalive(Some(Duration::from_secs(20)))
            .add_service(mpc_service)
            .serve(bind.parse().context("parsing bind address")?),
    );
    eprintln!("celar-kms-node[{}]: mTLS MPC server on {bind}", cfg.role);
    tokio::time::sleep(Duration::from_secs(cfg.startup_wait_secs)).await;

    // In-place: every seat is Both{set1: r, set2: r}. Two role→Identity maps over
    // the SAME peers — one keyed by TwoSetsRole, one by Role.
    let ident = |p: &PeerEntry| {
        Identity::new(
            p.host.clone(),
            p.port,
            Some(p.mpc.clone().unwrap_or_else(|| p.host.clone())),
        )
    };
    let my_both = TwoSetsRole::Both(DualRole {
        role_set_1: my_r,
        role_set_2: my_r,
    });
    let ts_assignment: RoleAssignment<TwoSetsRole> =
        HashMap::from_iter(cfg.peers.iter().map(|p| {
            let r = Role::indexed_from_one(p.role);
            (
                TwoSetsRole::Both(DualRole {
                    role_set_1: r,
                    role_set_2: r,
                }),
                ident(p),
            )
        }))
        .into();
    let ts_roles: std::collections::HashSet<TwoSetsRole> =
        ts_assignment.keys().cloned().collect();

    let s2_assignment: RoleAssignment<Role> =
        HashMap::from_iter(cfg.peers.iter().map(|p| (Role::indexed_from_one(p.role), ident(p))))
            .into();
    let s2_roles: std::collections::HashSet<Role> = s2_assignment.keys().cloned().collect();

    let sid_common = SessionId::from(cfg.session_id as u128);
    let sid_s2 = SessionId::from(cfg.session_id as u128 + 1);

    // Combined two-sets session (cross-set channel).
    let net_common = manager
        .make_network_session(sid_common, &ts_assignment, my_both, NetworkMode::Sync)
        .await
        .context("creating the two-sets network session")?;
    let params_common = GenericSessionParameters::<TwoSetsRole>::new(
        TwoSetsThreshold {
            threshold_set_1: old_degree as u8,
            threshold_set_2: new_degree as u8,
        },
        sid_common,
        my_both,
        ts_roles.clone(),
    )
    .map_err(|e| anyhow::anyhow!("two-sets session parameters: {e:?}"))?;
    let common =
        GenericBaseSession::<TwoSetsRole>::new(params_common, net_common, AesRng::from_random_seed())
            .map_err(|e| anyhow::anyhow!("two-sets base session: {e:?}"))?;
    common
        .network()
        .set_timeout_for_next_round(Duration::from_secs(cfg.round_timeout_secs))
        .await;

    // Set-2 (new committee) session.
    let net_s2 = manager
        .make_network_session(sid_s2, &s2_assignment, my_r, NetworkMode::Sync)
        .await
        .context("creating the set-2 network session")?;
    let params_s2 = SessionParameters::new(new_degree as u8, sid_s2, my_r, s2_roles)
        .map_err(|e| anyhow::anyhow!("set-2 session parameters: {e:?}"))?;
    let s2 = BaseSession::new(params_s2, net_s2, AesRng::from_random_seed())
        .map_err(|e| anyhow::anyhow!("set-2 base session: {e:?}"))?;
    s2.network()
        .set_timeout_for_next_round(Duration::from_secs(cfg.round_timeout_secs))
        .await;

    // Dummy resharing preprocessing, sized by upstream's accounting. Scoped so
    // the borrow of `s2` ends before it is moved into the reshare call.
    let n_s1 = ts_roles.iter().filter(|p| p.is_set1()).count();
    let (mut preproc64, mut preproc128) = {
        let mut dp = DummyPreprocessing::new(42, &s2);
        let req = ResharePreprocRequired::new(n_s1, params, oprf);
        let p64 = InMemoryBasePreprocessing::<ResiduePoly<Z64, EXTENSION_DEGREE>> {
            available_triples: Vec::new(),
            available_randoms: dp
                .next_random_vec(req.batch_params_64.randoms)
                .map_err(|e| anyhow::anyhow!("Z64 randoms: {e:?}"))?,
        };
        let p128 = InMemoryBasePreprocessing::<ResiduePoly<Z128, EXTENSION_DEGREE>> {
            available_triples: Vec::new(),
            available_randoms: dp
                .next_random_vec(req.batch_params_128.randoms)
                .map_err(|e| anyhow::anyhow!("Z128 randoms: {e:?}"))?,
        };
        (p64, p128)
    };

    eprintln!(
        "celar-kms-node[{}]: distributed upward reshare (degree {old_degree}->{new_degree}, {n} seats)…",
        cfg.role
    );
    let started = Instant::now();
    let new_share = SecureReshareSecretKeys::reshare_sk_two_sets_as_both_sets(
        &mut (common, s2),
        &mut preproc128,
        &mut preproc64,
        &mut my_share,
        params,
        oprf,
    )
    .await
    .map_err(|e| anyhow::anyhow!("distributed reshare failed: {e:?}"))?;
    let wall_secs = started.elapsed().as_secs_f64();

    fs::create_dir_all(out_dir)?;
    let bytes = bincode::serialize(&new_share).context("serializing new degree-d share")?;
    fs::write(out_dir.join(share_file(cfg.role)), &bytes)?;
    let fragment = ReshareResultFragment {
        schema: RESHARE_RESULT_SCHEMA.to_string(),
        role: cfg.role,
        parties: n,
        old_degree,
        new_degree,
        new_share_sha256: sha256_hex(&bytes),
        wall_secs,
    };
    fs::write(
        out_dir.join(reshare_result_file(cfg.role)),
        serde_json::to_string_pretty(&fragment)?,
    )?;
    println!(
        "RESHARE-OK role={} degree {}->{} wall={:.2}s share {}",
        cfg.role,
        old_degree,
        new_degree,
        wall_secs,
        out_dir.join(share_file(cfg.role)).display(),
    );
    eprintln!(
        "celar-kms-node[{}]: new share written; STAYING UP to serve peers — \
         stop only after all seats have finished.",
        cfg.role
    );
    let _ = server_handle.await;
    Ok(fragment)
}

#[cfg(test)]
mod endorsement_tests {
    use super::*;
    use crate::committee::{CommitteeMode, CommitteeRoster, RosterMember, ROSTER_SCHEMA};
    use crate::config::ParamsChoice;
    use crate::transcript::sha256_hex;
    use ed25519_dalek::{Signer, SigningKey};

    /// A dev roster of `c` seats plus the matching signing keys (role-indexed),
    /// so a test can produce genuine seat endorsements. c=8 ⇒ quorum = 7.
    fn roster_with_keys(c: usize) -> (CommitteeRoster, Vec<SigningKey>) {
        let mut members = Vec::new();
        let mut keys = Vec::new();
        for role in 1..=c {
            let mut seed = [0u8; 32];
            seed[0] = role as u8;
            seed[1] = (role >> 8) as u8;
            let sk = SigningKey::from_bytes(&seed);
            members.push(RosterMember {
                role,
                org: format!("org-{role}"),
                jurisdiction: None,
                host: format!("h{role}"),
                port: 51000 + role as u16,
                mpc_identity: format!("id{role}"),
                ca_cert_sha256: sha256_hex(format!("ca{role}").as_bytes()),
                signing_pubkey: hex::encode(sk.verifying_key().to_bytes()),
            });
            keys.push(sk);
        }
        let roster = CommitteeRoster {
            schema: ROSTER_SCHEMA.into(),
            mode: CommitteeMode::Dev,
            tag: "t".into(),
            params: ParamsChoice::Test,
            members,
        };
        (roster, keys)
    }

    /// A fragment over one fixed transcript (only `role` and `endorsement`
    /// vary), so every seat's `endorsement_digest()` is identical.
    fn base_fragment(role: usize) -> TranscriptFragment {
        TranscriptFragment {
            schema: FRAGMENT_SCHEMA.into(),
            role,
            committee_parties: 8,
            session_id: 1,
            params: "PARAMS_TEST_BK_SNS".into(),
            tag: "t".into(),
            pk_g_sha256: "aa".repeat(32),
            share_commitment_sha256: format!("{:02x}", role).repeat(32),
            wall_secs: 1.0,
            transport: "test".into(),
            roster_sha256: Some("cc".repeat(32)),
            endorsement: None,
        }
    }

    fn signed_by(role: usize, sk: &SigningKey) -> TranscriptFragment {
        let mut f = base_fragment(role);
        let d = f.endorsement_digest();
        f.endorsement = Some(hex::encode(sk.sign(d.as_bytes()).to_bytes()));
        f
    }

    #[test]
    fn a_quorum_of_real_endorsements_verifies() {
        let (roster, keys) = roster_with_keys(8); // quorum 7
        let frags: Vec<_> = (1..=8).map(|r| signed_by(r, &keys[r - 1])).collect();
        assert_eq!(verify_quorum_endorsement(&frags, &roster).unwrap(), 8);
    }

    #[test]
    fn a_forged_submission_without_endorsements_is_rejected() {
        // The attacker composes arbitrary transcript content that passes the
        // structural checks but carries NO real seat signatures. Authorship is
        // absent, so it must not reach a quorum.
        let (roster, _keys) = roster_with_keys(8);
        let frags: Vec<_> = (1..=8).map(base_fragment).collect(); // all unsigned
        assert!(
            verify_quorum_endorsement(&frags, &roster).is_err(),
            "an unsigned/forged submission must never authenticate"
        );
    }

    #[test]
    fn a_sub_quorum_of_endorsements_is_rejected() {
        let (roster, keys) = roster_with_keys(8); // quorum 7
        let frags: Vec<_> = (1..=6).map(|r| signed_by(r, &keys[r - 1])).collect();
        assert!(verify_quorum_endorsement(&frags, &roster).is_err());
    }

    #[test]
    fn a_signature_from_the_wrong_key_does_not_count() {
        let (roster, keys) = roster_with_keys(8); // quorum 7
        // Six genuine endorsements, plus role 7 presenting a signature made
        // with role 1's key — it verifies against member 1, not member 7, so it
        // must not count toward role 7. Result: 6 valid < quorum 7 → rejected.
        let mut frags: Vec<_> = (1..=6).map(|r| signed_by(r, &keys[r - 1])).collect();
        let mut forged = base_fragment(7);
        let d = forged.endorsement_digest();
        forged.endorsement = Some(hex::encode(keys[0].sign(d.as_bytes()).to_bytes()));
        frags.push(forged);
        assert!(
            verify_quorum_endorsement(&frags, &roster).is_err(),
            "a signature under the wrong seat's key must not count"
        );
    }

    #[test]
    fn endorsement_digest_ignores_per_seat_fields() {
        // Two seats differ only in the per-seat share commitment; their
        // endorsement digests must match so a quorum signs one value.
        let mut a = base_fragment(1);
        let mut b = base_fragment(2);
        a.share_commitment_sha256 = "11".repeat(32);
        b.share_commitment_sha256 = "22".repeat(32);
        assert_eq!(a.endorsement_digest(), b.endorsement_digest());
        // …but a different pk_G is a different transcript.
        let mut c = base_fragment(1);
        c.pk_g_sha256 = "dd".repeat(32);
        assert_ne!(a.endorsement_digest(), c.endorsement_digest());
    }
}
