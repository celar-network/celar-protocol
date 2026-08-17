//! celar-dkg — run a local genesis-mode DKG and publish its transcript, or
//! re-verify a published transcript. B1 skeleton CLI.
//!
//!   celar-dkg run    [--parties N] [--config cfg.json] [--out DIR] [--write-dev-keys]
//!   celar-dkg verify --transcript FILE [--keys-dir DIR]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use celar_kms::config::{CommitteeConfig, PreprocMode};
use celar_kms::dkg::run_local_dkg;
use celar_kms::transcript::Transcript;

#[derive(Parser)]
#[command(name = "celar-dkg", version, about = "Celar Track B — DKG (B1 skeleton)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a local n-party DKG and write transcript.json (+ optional dev keys).
    Run {
        /// Committee size c (ignored if --config is given). Genesis range is
        /// 30–50; smaller runs are marked as dev profile in the transcript.
        #[arg(long, default_value_t = 4)]
        parties: usize,
        /// JSON CommitteeConfig file; overrides --parties/--preproc.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Offline phase: dummy (dev, seconds) | secure (real MPC offline
        /// phase — ceremony-grade, long wall-clock).
        #[arg(long, default_value = "dummy")]
        preproc: String,
        /// Output directory.
        #[arg(long, default_value = "dkg-out")]
        out: PathBuf,
        /// Also write pk_G and per-party shares (DEV ONLY) so `verify
        /// --keys-dir` can recompute every digest.
        #[arg(long, default_value_t = false)]
        write_dev_keys: bool,
    },
    /// Verify a transcript: internal consistency, plus digest recomputation
    /// if a keys directory is given.
    Verify {
        #[arg(long)]
        transcript: PathBuf,
        #[arg(long)]
        keys_dir: Option<PathBuf>,
    },
    /// B5: proactive same-set reshare — new epoch of shares from the previous
    /// epoch's dev share files; pk_G invariant; optional recovery demo.
    Reshare {
        /// Directory holding the previous epoch (transcript.json or
        /// reshare.json + party share files).
        #[arg(long = "in", value_name = "DIR")]
        in_dir: PathBuf,
        #[arg(long, default_value = "epoch-out")]
        out: PathBuf,
        /// Simulate a party that LOST its share: it joins with none and must
        /// recover a fresh one (§7.5 recovery property).
        #[arg(long)]
        drop_role: Option<usize>,
    },
    /// Verify a reshare transcript against its predecessor (+ keys dir).
    VerifyReshare {
        #[arg(long)]
        transcript: PathBuf,
        /// The PREVIOUS epoch's transcript file (genesis transcript.json or
        /// earlier reshare.json).
        #[arg(long)]
        prev: PathBuf,
        #[arg(long)]
        keys_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run {
            parties,
            config,
            preproc,
            out,
            write_dev_keys,
        } => {
            let cfg = match config {
                Some(path) => {
                    let json = std::fs::read_to_string(&path)
                        .with_context(|| format!("reading config {}", path.display()))?;
                    serde_json::from_str::<CommitteeConfig>(&json)?
                }
                None => CommitteeConfig {
                    parties,
                    preprocessing: match preproc.as_str() {
                        "dummy" => PreprocMode::Dummy,
                        "secure" => PreprocMode::Secure,
                        other => anyhow::bail!(
                            "unknown --preproc {other:?} (expected dummy | secure)"
                        ),
                    },
                    ..Default::default()
                },
            };
            cfg.validate()?;

            eprintln!(
                "celar-dkg: c={} t_reconstruction={} t_session={} params={} preproc={} ({} profile)",
                cfg.parties,
                cfg.reconstruction_quorum(),
                cfg.session_threshold(),
                cfg.params.name(),
                cfg.preprocessing.label(),
                if cfg.is_genesis_scale() { "genesis" } else { "dev" },
            );
            if cfg.preprocessing == PreprocMode::Secure {
                eprintln!(
                    "celar-dkg: SECURE offline phase — real MPC triple/randomness \
                     generation; expect a long run"
                );
            }
            eprintln!("celar-dkg: running local {}-party DKG…", cfg.parties);

            let outcome = run_local_dkg(&cfg, &out, write_dev_keys).await?;
            println!(
                "DKG-OK preproc={} wall={:.1}s pk_G {} transcript {}",
                outcome.transcript.dkg.preprocessing,
                outcome.transcript.dkg.wall_secs.unwrap_or(f64::NAN),
                outcome.transcript.pk_g_sha256,
                out.join("transcript.json").display()
            );
            Ok(())
        }
        Cmd::Verify {
            transcript,
            keys_dir,
        } => {
            let t = Transcript::load(&transcript)?;
            match keys_dir {
                Some(dir) => {
                    t.verify_against_keys(&dir)?;
                    println!("VERIFY-OK (level 2: transcript + key digests recomputed)");
                }
                None => {
                    t.verify_internal()?;
                    println!("VERIFY-OK (level 1: internal consistency)");
                }
            }
            Ok(())
        }
        Cmd::Reshare { in_dir, out, drop_role } => {
            eprintln!(
                "celar-dkg: proactive same-set reshare from {}{}",
                in_dir.display(),
                drop_role
                    .map(|r| format!(" (party {r} simulates share LOSS + recovery)"))
                    .unwrap_or_default(),
            );
            let outcome = celar_kms::reshare::run_local_reshare(
                &in_dir,
                &out,
                drop_role,
            )
            .await?;
            println!(
                "RESHARE-OK epoch={} wall={:.1}s pk_G {} (INVARIANT) transcript {}",
                outcome.transcript.epoch,
                outcome.transcript.wall_secs,
                outcome.transcript.pk_g_sha256,
                out.join("reshare.json").display(),
            );
            Ok(())
        }
        Cmd::VerifyReshare {
            transcript,
            prev,
            keys_dir,
        } => {
            let t = celar_kms::reshare::ReshareTranscript::load(&transcript)?;
            t.verify_against_prev(&prev)?;
            if let Some(dir) = keys_dir {
                t.verify_against_keys(&dir)?;
                println!(
                    "RESHARE-VERIFY-OK epoch={} (chain + pk_G invariant + all commitments changed + key digests recomputed)",
                    t.epoch
                );
            } else {
                println!(
                    "RESHARE-VERIFY-OK epoch={} (chain + pk_G invariant + all commitments changed)",
                    t.epoch
                );
            }
            Ok(())
        }
    }
}
