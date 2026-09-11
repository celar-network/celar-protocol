//! celar-kms-node — Celar KMS ceremony node (mTLS ceremony hardening).
//!
//!   celar-kms-node gen-configs --parties 4 --base-port 51000 --certs-dir certs \
//!                              --out-dir ceremony        # write n node configs
//!   celar-kms-node run --config ceremony/node_001.json   # one per terminal/host
//!   celar-kms-node collect --dir ceremony                # fragments → transcript
//!
//! TLS certs come from the upstream generator (same repo pin), exposed here
//! as the `celar-certs` binary: e.g.
//!   celar-certs --ca-prefix party --ca-count 4 -n 1 -o certs

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use celar_kms::config::CommitteeConfig;
use celar_kms::node::{
    fragment_file, run_ceremony, NodeConfig, PeerEntry, TlsPaths, TranscriptFragment,
    FRAGMENT_SCHEMA,
};
use celar_kms::transcript::{PartyRecord, Transcript};

#[derive(Parser)]
#[command(name = "celar-kms-node", version, about = "Celar KMS — networked ceremony node (gRPC/mTLS)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// write a committee roster from a certs directory (dev helper —
    /// computes the real CA pins; a production roster is authored during
    /// vetting, not generated).
    RosterInit {
        #[arg(long, default_value_t = 4)]
        parties: usize,
        #[arg(long, default_value = "certs")]
        certs_dir: PathBuf,
        /// CA cert filename pattern ({i} = role) — the pinned files.
        #[arg(long, default_value = "cert_party{i}.pem")]
        ca_pattern: String,
        #[arg(long, default_value = "core1.party{i}")]
        host_pattern: String,
        #[arg(long, default_value_t = 51000)]
        base_port: u16,
        /// dev | permissioned-genesis (genesis enforces c ∈ [30,50] etc.)
        #[arg(long, default_value = "dev")]
        mode: String,
        #[arg(long, default_value = "roster.json")]
        out: PathBuf,
    },
    /// Write n node-config JSONs for a local ceremony (one process each).
    GenConfigs {
        #[arg(long, default_value_t = 4)]
        parties: usize,
        #[arg(long, default_value_t = 51000)]
        base_port: u16,
        /// Directory containing certs from `celar-certs` (--ca-prefix party).
        #[arg(long, default_value = "certs")]
        certs_dir: PathBuf,
        /// Peer hostname pattern; `{i}` = one-based role index. Upstream's
        /// TLS layer requires hostnames (IPs are rejected for SNI), so for a
        /// local ceremony these names must resolve to 127.0.0.1 (/etc/hosts)
        /// and match the cert SANs.
        #[arg(long, default_value = "party{i}")]
        host_pattern: String,
        /// MPC-identity pattern = the cert subject/SAN of each party's core
        /// cert (upstream generator: "party{i}-core1"). `{i}` substituted.
        #[arg(long, default_value = "party{i}-core1")]
        mpc_pattern: String,
        /// Filename patterns inside certs-dir; `{i}` = one-based role index.
        #[arg(long, default_value = "cert_party{i}-core1.pem")]
        cert_pattern: String,
        #[arg(long, default_value = "key_party{i}-core1.pem")]
        key_pattern: String,
        #[arg(long, default_value = "cert_party{i}.pem")]
        ca_pattern: String,
        #[arg(long, default_value = "ceremony")]
        out_dir: PathBuf,
        #[arg(long, default_value_t = false)]
        write_dev_keys: bool,
        /// govern the ceremony by a vetted roster (peers, MPC identities
        /// and committee size come FROM the roster; nodes verify CA pins).
        #[arg(long)]
        roster: Option<PathBuf>,
    },
    /// Run this node's side of the ceremony (blocks until DKG completes).
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Merge n fragments into the canonical transcript; checks pk_G equality.
    Collect {
        #[arg(long, default_value = "ceremony")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Surface upstream tracing (dropped messages, identity mismatches, …):
    //   RUST_LOG=info ./celar_kms_node run …
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // rustls has both aws-lc-rs and ring in the dependency graph, so the
    // process-level CryptoProvider must be installed explicitly (upstream's
    // moby does exactly this). Must run before any TLS config is built.
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls CryptoProvider"))?;

    match Cli::parse().cmd {
        Cmd::RosterInit {
            parties,
            certs_dir,
            ca_pattern,
            host_pattern,
            base_port,
            mode,
            out,
        } => {
            use celar_kms::committee::{
                CommitteeMode, CommitteeRoster, RosterMember, ROSTER_SCHEMA,
            };
            use celar_kms::transcript::sha256_hex;
            let mode = match mode.as_str() {
                "dev" => CommitteeMode::Dev,
                "permissioned-genesis" => CommitteeMode::PermissionedGenesis,
                other => anyhow::bail!("unknown --mode {other:?}"),
            };
            let members = (1..=parties)
                .map(|i| -> Result<RosterMember> {
                    let ca_path = certs_dir.join(ca_pattern.replace("{i}", &i.to_string()));
                    let pin = sha256_hex(&fs::read(&ca_path).with_context(|| {
                        format!("reading CA file {} for pinning", ca_path.display())
                    })?);
                    let host = host_pattern.replace("{i}", &i.to_string());
                    Ok(RosterMember {
                        role: i,
                        org: format!("dev-org-{i}"),
                        jurisdiction: None,
                        host: host.clone(),
                        port: base_port + i as u16,
                        mpc_identity: host,
                        ca_cert_sha256: pin,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let roster = CommitteeRoster {
                schema: ROSTER_SCHEMA.to_string(),
                mode,
                tag: "celar-genesis-dev".into(),
                params: celar_kms::config::ParamsChoice::Test,
                members,
            };
            roster.save(&out)?;
            println!(
                "ROSTER-OK {} members, quorum {}, digest {} → {}",
                roster.parties(),
                roster.reconstruction_quorum(),
                roster.digest()?,
                out.display()
            );
            Ok(())
        }
        Cmd::GenConfigs {
            parties,
            base_port,
            certs_dir,
            host_pattern,
            mpc_pattern,
            cert_pattern,
            key_pattern,
            ca_pattern,
            out_dir,
            write_dev_keys,
            roster,
        } => {
            fs::create_dir_all(&out_dir)?;

            // a roster, when given, is the source of truth for the
            // committee shape and every peer's identity.
            let loaded_roster = roster
                .as_ref()
                .map(|p| celar_kms::committee::CommitteeRoster::load(p))
                .transpose()?;

            let (committee, peers): (CommitteeConfig, Vec<PeerEntry>) = match &loaded_roster {
                Some(r) => (
                    r.committee_config()?,
                    r.members
                        .iter()
                        .map(|m| PeerEntry {
                            role: m.role,
                            host: m.host.clone(),
                            port: m.port,
                            mpc: Some(m.mpc_identity.clone()),
                        })
                        .collect(),
                ),
                None => {
                    let committee = CommitteeConfig {
                        parties,
                        preprocessing: celar_kms::config::PreprocMode::Secure,
                        ..Default::default()
                    };
                    committee.validate()?;
                    let peers = (1..=parties)
                        .map(|i| PeerEntry {
                            role: i,
                            host: host_pattern.replace("{i}", &i.to_string()),
                            port: base_port + i as u16,
                            mpc: Some(mpc_pattern.replace("{i}", &i.to_string())),
                        })
                        .collect();
                    (committee, peers)
                }
            };
            let parties = committee.parties;
            let pat = |p: &str, i: usize| {
                certs_dir.join(p.replace("{i}", &i.to_string())).display().to_string()
            };
            let calist = (1..=parties).map(|i| pat(&ca_pattern, i)).collect::<Vec<_>>().join(",");

            for i in 1..=parties {
                let cfg = NodeConfig {
                    role: i,
                    listen_addr: "0.0.0.0".into(),
                    peers: peers.clone(),
                    tls: TlsPaths {
                        cert: pat(&cert_pattern, i),
                        key: pat(&key_pattern, i),
                        calist: calist.clone(),
                    },
                    committee: committee.clone(),
                    session_id: 1,
                    round_timeout_secs: 600,
                    startup_wait_secs: 5,
                    out_dir: out_dir.clone(),
                    write_dev_keys,
                    roster: roster.clone(),
                    // Absent → committee-scale transport defaults at run time.
                    net: None,
                };
                let path = out_dir.join(format!("node_{i:03}.json"));
                fs::write(&path, serde_json::to_string_pretty(&cfg)?)?;
                println!("wrote {}", path.display());
            }
            println!(
                "start each node:  celar-kms-node run --config {}/node_00N.json",
                out_dir.display()
            );
            Ok(())
        }
        Cmd::Run { config } => {
            let cfg = NodeConfig::load(&config)?;
            let fragment = run_ceremony(&cfg).await?;
            println!(
                "CEREMONY-OK role={} wall={:.1}s pk_G {} fragment {}",
                fragment.role,
                fragment.wall_secs,
                fragment.pk_g_sha256,
                cfg.out_dir.join(fragment_file(fragment.role)).display(),
            );
            Ok(())
        }
        Cmd::Collect { dir } => {
            // Load whatever fragments exist, in role order.
            let mut fragments: Vec<TranscriptFragment> = Vec::new();
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                if name.starts_with("fragment_") && name.ends_with(".json") {
                    let f: TranscriptFragment =
                        serde_json::from_str(&fs::read_to_string(&path)?)
                            .with_context(|| format!("parsing {}", path.display()))?;
                    if f.schema != FRAGMENT_SCHEMA {
                        bail!("{}: unknown fragment schema {:?}", path.display(), f.schema);
                    }
                    fragments.push(f);
                }
            }
            if fragments.is_empty() {
                bail!("no fragment_*.json in {}", dir.display());
            }
            fragments.sort_by_key(|f| f.role);

            let first = &fragments[0];
            let c = first.committee_parties;
            if fragments.len() != c {
                bail!(
                    "found {}/{} fragments — ceremony incomplete, refusing to collect",
                    fragments.len(),
                    c
                );
            }
            for f in &fragments {
                if f.pk_g_sha256 != first.pk_g_sha256 {
                    bail!(
                        "pk_G MISMATCH: role {} has {} vs role {}'s {} — protocol violation",
                        f.role, f.pk_g_sha256, first.role, first.pk_g_sha256
                    );
                }
                if (f.params != first.params)
                    || (f.tag != first.tag)
                    || (f.session_id != first.session_id)
                {
                    bail!("fragment {} disagrees on params/tag/session_id", f.role);
                }
                // either every node ran under the SAME roster, or none did.
                if f.roster_sha256 != first.roster_sha256 {
                    bail!(
                        "fragment {} ran under a different roster ({:?} vs {:?}) — \
                         refusing to collect a mixed ceremony",
                        f.role, f.roster_sha256, first.roster_sha256
                    );
                }
            }

            let committee = CommitteeConfig {
                parties: c,
                preprocessing: celar_kms::config::PreprocMode::Secure,
                tag: first.tag.clone(),
                ..Default::default()
            };
            let parties = fragments
                .iter()
                .map(|f| PartyRecord {
                    role: f.role,
                    share_commitment_sha256: f.share_commitment_sha256.clone(),
                })
                .collect();
            let max_wall = fragments.iter().map(|f| f.wall_secs).fold(0.0_f64, f64::max);
            let mut transcript = Transcript::build(
                &committee,
                first.session_id,
                first.pk_g_sha256.clone(),
                parties,
                Some(max_wall),
            );
            transcript.mode = format!(
                "{}-grpc-mtls-secure-small-preproc",
                if committee.is_genesis_scale() { "genesis" } else { "dev" },
            );
            transcript.roster_sha256 = first.roster_sha256.clone();
            transcript.save(&dir.join("transcript.json"))?;
            transcript.verify_internal()?;
            println!(
                "COLLECT-OK {} fragments, pk_G {}, transcript {}",
                fragments.len(),
                first.pk_g_sha256,
                dir.join("transcript.json").display()
            );
            Ok(())
        }
    }
}
