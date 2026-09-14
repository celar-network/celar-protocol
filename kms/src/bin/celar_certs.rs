//! celar-certs — identity generation for the KMS ceremony nodes.
//!
//! Two identities per seat, produced in one pass:
//!   1. the mTLS certificate set — a thin passthrough to the upstream
//!      generator (`threshold-networking` `tls_certs`), so certificates are
//!      exactly the shape the mTLS networking stack expects;
//!   2. an ed25519 OPERATIONAL SIGNING keypair — the seat's transcript-
//!      endorsement identity, distinct from its TLS identity. The roster
//!      registers the public key; the private key stays on the seat and signs
//!      ceremony/reshare transcript digests so an archived epoch carries
//!      reconstruction-quorum-many seat endorsements (the authorship a bare
//!      hash chain cannot supply).
//!
//! Example for a 4-party dev ceremony:
//!
//!   celar-certs --ca-prefix party --ca-count 4 -n 1 -o certs
//!
//! produces the TLS files plus, per seat i, `signing_party{i}.key` (private,
//! 64-hex — NEVER commit or distribute beyond the seat) and
//! `signing_party{i}.pub` (public, 64-hex — read into the roster at
//! `roster-init`). Then check `ls certs/` and align `celar-kms-node
//! gen-configs`'s --cert-pattern/--key-pattern/--ca-pattern with the names.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    // 1) mTLS certs — the upstream generator parses argv itself.
    threshold_networking::tls_certs::entry_point().await?;
    // 2) ed25519 operational signing keys into the same output dir. We read
    //    the same flags the generator accepts (no NEW args, so its strict
    //    parse is unaffected) rather than re-parsing with a second clap.
    generate_signing_keys().context("generating operational signing keys")?;
    Ok(())
}

/// Emit one ed25519 keypair per seat into the cert output directory, named to
/// mirror the CA files so `roster-init` can find them by the same `{i}` index.
fn generate_signing_keys() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };

    let prefix = flag("--ca-prefix").unwrap_or_else(|| "party".to_string());
    let count: usize = flag("--ca-count")
        .context("--ca-count is required")?
        .parse()
        .context("--ca-count is not a number")?;
    let out = PathBuf::from(
        flag("-o")
            .or_else(|| flag("--output-dir"))
            .unwrap_or_else(|| "certs".to_string()),
    );

    for i in 1..=count {
        let sk = SigningKey::generate(&mut OsRng);
        let base = format!("{prefix}{i}");
        let key_path = out.join(format!("signing_{base}.key"));
        let pub_path = out.join(format!("signing_{base}.pub"));
        fs::write(&key_path, hex::encode(sk.to_bytes()))
            .with_context(|| format!("writing {}", key_path.display()))?;
        let pub_hex = hex::encode(sk.verifying_key().to_bytes());
        fs::write(&pub_path, &pub_hex)
            .with_context(|| format!("writing {}", pub_path.display()))?;
        println!("SIGNING-KEY {base} pub {pub_hex}");
    }
    Ok(())
}
