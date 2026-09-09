//! celar-dkg — run a local genesis-mode DKG and publish its transcript, or
//! re-verify a published transcript. Skeleton CLI.
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
#[command(name = "celar-dkg", version, about = "Celar KMS — distributed key generation")]
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
        /// Offline phase: dummy (dev, seconds) | secure (real, PRSS,
        /// small committees only) | secure-large (real, genesis-scale).
        #[arg(long, default_value = "dummy")]
        preproc: String,
        /// secure-large offline chunk size (triples/randoms per
        /// sub-protocol run). Trades peak memory against rounds.
        #[arg(long, default_value_t = 2048)]
        preproc_chunk: usize,
        /// Override the upstream session corruption bound t. The
        /// secure-large path requires c ≥ 4t+1 (t < n/4), stricter than
        /// the ⌊(c−1)/3⌋ default — e.g. c=13 needs t ≤ 3.
        #[arg(long)]
        session_threshold: Option<usize>,
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
    /// Proactive same-set reshare — new epoch of shares from the previous
    /// epoch's dev share files; pk_G invariant; optional recovery demo.
    Reshare {
        /// Directory holding the previous epoch (transcript.json or
        /// reshare.json + party share files).
        /// Offline randomness: dummy (dev, seeded from the previous
        /// transcript digest) | secure-large (real, genesis-capable; needs
        /// c ≥ 4t+1). There is no PRSS reshare mode, deliberately.
        #[arg(long, default_value = "dummy")]
        preproc: String,
        #[arg(long = "in", value_name = "DIR")]
        in_dir: PathBuf,
        #[arg(long, default_value = "epoch-out")]
        out: PathBuf,
        /// Simulate a party that LOST its share: it joins with none and must
        /// recover a fresh one (§7.5 recovery property).
        #[arg(long)]
        drop_role: Option<usize>,
    },
    /// Upward reshare (§7.5, degree-decoupled): reshare the key held by the
    /// previous epoch's committee UP to a larger committee at a HIGHER sharing
    /// degree, decoupling the key's degree from the committee's corruption
    /// threshold. Dummy preprocessing (dev) — the secure genesis offline is a
    /// contribution-sum construction tracked separately, not the MPC offline.
    UpwardReshare {
        /// Directory holding the previous epoch (transcript.json or
        /// reshare.json + share files) — the OLD committee (set 1).
        #[arg(long = "in", value_name = "DIR")]
        in_dir: PathBuf,
        #[arg(long, default_value = "upward-epoch-out")]
        out: PathBuf,
        /// New committee size (set 2).
        #[arg(long)]
        new_parties: usize,
        /// New sharing degree (set 2) — the decoupled degree; must exceed the
        /// old committee's degree.
        #[arg(long)]
        new_threshold: usize,
        /// Parties present in BOTH the old and new committees.
        #[arg(long, default_value_t = 0)]
        intersection: usize,
    },
    /// N-party noise-flooded threshold decryption of a fixture value
    /// encrypted under the DKG's pk_G. --shares-dir may point at a LATER
    /// epoch (resharing functional proof: reshared shares decrypt the same pk_G).
    Decrypt {
        /// Directory with transcript.json + pk_g.bin (genesis DKG output).
        #[arg(long)]
        keys_dir: PathBuf,
        /// Directory with the party share files (default: keys-dir).
        #[arg(long)]
        shares_dir: Option<PathBuf>,
        /// Fixture plaintext to encrypt and threshold-decrypt.
        #[arg(long, default_value_t = 42)]
        value: u64,
        /// Session family: large (PRODUCTION — TUniform flooding at 52,
        /// scales to genesis, backs the §7.2 budget; needs c ≥ 4t+1) |
        /// small (DEV — PRSS at 40, small committees, does not back the
        /// budget).
        #[arg(long, default_value = "large")]
        session: String,
        #[arg(long, default_value = "decrypt-report.json")]
        out: PathBuf,
    },
    /// Measure the raw (unflooded) post-switch-and-squash noise using dev
    /// keys: encrypts zero, reconstructs without masks, logs |e|. The
    /// observed distribution anchors the analytical bound verdict.
    NoiseProbe {
        #[arg(long)]
        keys_dir: PathBuf,
        /// Number of ciphertexts (each contributes several block samples).
        #[arg(long, default_value_t = 500)]
        ciphertexts: usize,
        /// Transfer-shaped homomorphic rounds (le/select/sub/add) applied
        /// before squashing. 0 = fresh encryption; operational ciphertexts
        /// are post-computation, which is what the bound must cover.
        #[arg(long, default_value_t = 0)]
        chain_ops: usize,
        #[arg(long, default_value = "noise-probe.json")]
        out: PathBuf,
    },
    /// CENTRALIZED noise probe — one keyset, full-key raw phase. The
    /// production-parameter path: measures the same post-squash noise as
    /// `noise-probe` but without the multi-party memory that OOMs at NIST
    /// params. No DKG, no keys-dir.
    NoiseProbeCentral {
        /// Parameter set: test (fast) | nist (production).
        #[arg(long, default_value = "test")]
        params: String,
        #[arg(long, default_value_t = 300)]
        ciphertexts: usize,
        #[arg(long, default_value_t = 0)]
        chain_ops: usize,
        #[arg(long, default_value = "noise-probe-central.json")]
        out: PathBuf,
    },
    /// Threshold RE-ENCRYPTION (§7.3) — seats produce masked partials,
    /// the requester combines them locally. No intermediary sees plaintext.
    Reencrypt {
        #[arg(long)]
        keys_dir: PathBuf,
        #[arg(long)]
        shares_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 42)]
        value: u64,
        /// Combine only the first K partials (quorum behaviour). Default: all.
        #[arg(long)]
        partials: Option<usize>,
        /// Scaling check: repeat one seat's partial decryption N times and
        /// require the cost to grow ~N-fold before any timing is quotable.
        #[arg(long, default_value_t = 1)]
        repeat: usize,
        #[arg(long, default_value = "reencrypt-report.json")]
        out: PathBuf,
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
            preproc_chunk,
            session_threshold,
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
                        "secure-large" => PreprocMode::SecureLarge,
                        other => anyhow::bail!(
                            "unknown --preproc {other:?} (expected dummy | secure | secure-large)"
                        ),
                    },
                    preproc_chunk,
                    session_threshold,
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
        Cmd::Reshare { preproc, in_dir, out, drop_role } => {
            let preproc_mode = match preproc.as_str() {
                "dummy" => PreprocMode::Dummy,
                "secure-large" => PreprocMode::SecureLarge,
                other => anyhow::bail!(
                    "unknown --preproc {other:?} (expected dummy | secure-large; \
                     there is no PRSS reshare mode)"
                ),
            };
            eprintln!(
                "celar-dkg: proactive same-set reshare (preproc={preproc}) from {}{}",
                in_dir.display(),
                drop_role
                    .map(|r| format!(" (party {r} simulates share LOSS + recovery)"))
                    .unwrap_or_default(),
            );
            let outcome = celar_kms::reshare::run_local_reshare(
                &in_dir,
                &out,
                drop_role,
                preproc_mode,
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
        Cmd::UpwardReshare {
            in_dir,
            out,
            new_parties,
            new_threshold,
            intersection,
        } => {
            eprintln!(
                "celar-dkg: upward reshare (dummy preproc) from {} -> {new_parties} parties \
                 at degree {new_threshold} (intersection {intersection})",
                in_dir.display(),
            );
            let t = celar_kms::reshare::run_local_upward_reshare(
                &in_dir,
                &out,
                new_parties,
                new_threshold,
                intersection,
            )
            .await?;
            println!(
                "UPWARD-RESHARE-OK old={}->new={} degree {}->{} wall={:.1}s pk_G {} (INVARIANT) transcript {}",
                t.old_committee_parties,
                t.new_committee_parties,
                t.old_degree,
                t.new_degree,
                t.wall_secs,
                t.pk_g_sha256,
                out.join("upward-reshare.json").display(),
            );
            Ok(())
        }
        Cmd::NoiseProbe { keys_dir, ciphertexts, chain_ops, out } => {
            eprintln!(
                "celar-dkg: noise probe — {} zero-ciphertexts, {} op-chain rounds, \
                 unflooded reconstruction, keys {}",
                ciphertexts,
                chain_ops,
                keys_dir.display()
            );
            let r = celar_kms::noise_probe::run_noise_probe(&keys_dir, ciphertexts, chain_ops, &out)?;
            println!(
                "NOISE-PROBE-OK chain_ops={} samples={} max_log2={:.1} p99={:.1} mean={:.1} \
                 assumed=70 observed_slack={:.1} bits report {}",
                r.chain_ops, r.samples, r.max_log2, r.p99_log2, r.mean_log2,
                r.observed_slack_bits, out.display()
            );
            Ok(())
        }
        Cmd::NoiseProbeCentral { params, ciphertexts, chain_ops, out } => {
            let params_choice = match params.as_str() {
                "test" => celar_kms::config::ParamsChoice::Test,
                "nist" => celar_kms::config::ParamsChoice::NistP32SnsFglwe,
                other => anyhow::bail!("unknown --params {other:?} (expected test | nist)"),
            };
            eprintln!(
                "celar-dkg: CENTRALIZED noise probe — {} zero-ciphertexts, {} op-chain rounds, \
                 single keyset at {}",
                ciphertexts, chain_ops, params_choice.name()
            );
            let r = celar_kms::noise_probe::run_noise_probe_centralized(
                params_choice, ciphertexts, chain_ops, &out,
            )?;
            println!(
                "NOISE-PROBE-CENTRAL-OK params={} chain_ops={} samples={} max_log2={:.1} \
                 p99={:.1} mean={:.1} assumed=70 observed_slack={:.1} bits report {}",
                r.params, r.chain_ops, r.samples, r.max_log2, r.p99_log2, r.mean_log2,
                r.observed_slack_bits, out.display()
            );
            Ok(())
        }
        Cmd::Decrypt {
            keys_dir,
            shares_dir,
            value,
            session,
            out,
        } => {
            let shares = shares_dir.clone().unwrap_or_else(|| keys_dir.clone());
            let session_kind = celar_kms::decrypt::DecryptSession::parse(&session)?;
            eprintln!(
                "celar-dkg: threshold decrypt (session={session}) — pk from {}, shares from {}",
                keys_dir.display(),
                shares.display()
            );
            let outcome = celar_kms::decrypt::run_local_threshold_decrypt(
                &keys_dir,
                &shares,
                value,
                session_kind,
                &out,
            )
            .await?;
            println!(
                "DECRYPT-OK mode={} parties={} value={} ALL-AGREE wall={:.1}s report {}",
                outcome.report.mode,
                outcome.report.parties,
                value,
                outcome.report.wall_secs,
                out.display()
            );
            Ok(())
        }
        Cmd::Reencrypt {
            keys_dir,
            shares_dir,
            value,
            partials,
            repeat,
            out,
        } => {
            let shares = shares_dir.clone().unwrap_or_else(|| keys_dir.clone());
            eprintln!(
                "celar-dkg: threshold RE-ENCRYPTION (§7.3) — masked partials from {}, \
                 combined client-side",
                shares.display()
            );
            let outcome = celar_kms::reencrypt::run_local_reencrypt(
                &keys_dir, &shares, value, partials, repeat, &out,
            )
            .await?;
            let r = &outcome.report;
            println!(
                "REENCRYPT-OK combined {}/{} partials value={}",
                r.partials_combined, r.parties, r.value_recovered,
            );
            println!(
                "  per-seat partial (COLD, incl. warm-up): min {:.4}s median {:.4}s max {:.4}s",
                r.seat_timings.min_secs, r.seat_timings.median_secs, r.seat_timings.max_secs,
            );
            match r.warm_per_iter_secs {
                Some(w) => println!(
                    "  steady-state per seat (WARM, {}x): {:.4}s | client combine {:.4}s | \
                     harness wall {:.4}s",
                    r.repeat, w, r.combine_secs, r.partial_secs
                ),
                None => println!(
                    "  steady-state: not measured (--repeat N) | client combine {:.4}s | \
                     harness wall {:.4}s",
                    r.combine_secs, r.partial_secs
                ),
            }
            println!(
                "  §7.3 latency: {}\n  {}",
                if !r.timing_valid {
                    "VOID — not quotable (correctness unaffected)".to_string()
                } else {
                    format!(
                        "{} at c={} on local runtime + test params — NOT a t≤100 claim",
                        if r.meets_2s_target { "under 2 s" } else { "OVER 2 s" },
                        r.parties
                    )
                },
                r.timing_note,
            );
            println!("  report {}", out.display());
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
