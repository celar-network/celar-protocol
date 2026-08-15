//! celar-dkg — run a local genesis-mode DKG and publish its transcript, or
//! re-verify a published transcript. B1 skeleton CLI.
//!
//!   celar-dkg run    [--parties N] [--config cfg.json] [--out DIR] [--write-dev-keys]
//!   celar-dkg verify --transcript FILE [--keys-dir DIR]

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use celar_kms::config::CommitteeConfig;
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
        /// JSON CommitteeConfig file; overrides --parties.
        #[arg(long)]
        config: Option<PathBuf>,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run {
            parties,
            config,
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
                    ..Default::default()
                },
            };
            cfg.validate()?;

            eprintln!(
                "celar-dkg: c={} t_reconstruction={} t_session={} params={} ({} profile)",
                cfg.parties,
                cfg.reconstruction_quorum(),
                cfg.session_threshold(),
                cfg.params.name(),
                if cfg.is_genesis_scale() { "genesis" } else { "dev" },
            );
            eprintln!("celar-dkg: running local {}-party DKG…", cfg.parties);

            let outcome = run_local_dkg(&cfg, &out, write_dev_keys).await?;
            println!(
                "DKG-OK pk_G {} transcript {}",
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
    }
}
