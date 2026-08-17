//! The DKG transcript artifact — §7.1's "published transcript + verification
//! scripts" deliverable, skeleton edition.
//!
//! The transcript is public: it carries the run's configuration, the upstream
//! pin, a digest of the group public keyset pk_G, and one hash COMMITMENT per
//! party's share vector. Shares themselves never enter the transcript.
//!
//! Re-verification levels:
//! - transcript alone → internal consistency (schema, quorum rule, digest
//!   shapes, party count);
//! - transcript + a keys directory (dev runs may write one) → digests are
//!   recomputed from the actual artifacts and compared.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::CommitteeConfig;

pub const SCHEMA: &str = "celar-dkg-transcript/v0";

/// File names inside a dev keys directory.
pub const PK_FILE: &str = "pk_g.bin";
pub fn share_file(role_one_based: usize) -> String {
    format!("party_{role_one_based:03}.share.bin")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub repo: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeRecord {
    pub parties: usize,
    pub reconstruction_quorum: usize,
    pub session_threshold: usize,
    pub genesis_scale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRecord {
    pub params: String,
    pub tag: String,
    pub session_id: u64,
    /// "dummy" or "secure-small" — verifiers must be able to tell which
    /// offline phase produced a transcript; only "secure-small" (or better)
    /// is ceremony-grade.
    pub preprocessing: String,
    pub preproc_seed: u64,
    /// Wall-clock of the protocol run (all parties, local). Artifact
    /// discipline: every number datable and attributable.
    #[serde(default)]
    pub wall_secs: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyRecord {
    /// One-based role index (upstream Role convention).
    pub role: usize,
    /// SHA-256 over the party's serialized private share vector.
    pub share_commitment_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub os: String,
    pub arch: String,
    /// Unix seconds; artifact discipline wants every number datable.
    pub created_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transcript {
    pub schema: String,
    pub mode: String,
    pub upstream: Upstream,
    pub committee: CommitteeRecord,
    pub dkg: DkgRecord,
    /// SHA-256 over the serialized group public keyset (identical across
    /// parties — checked at generation time).
    pub pk_g_sha256: String,
    /// B6: canonical digest of the vetted committee roster this ceremony ran
    /// under (None for dev runs without a roster). A transcript with a roster
    /// digest proves WHICH committee keyed the network, not just how many.
    #[serde(default)]
    pub roster_sha256: Option<String>,
    pub parties: Vec<PartyRecord>,
    pub environment: Environment,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl Transcript {
    pub fn build(
        cfg: &CommitteeConfig,
        session_id: u64,
        pk_g_sha256: String,
        parties: Vec<PartyRecord>,
        wall_secs: Option<f64>,
    ) -> Self {
        Self {
            schema: SCHEMA.to_string(),
            mode: format!(
                "{}-local-{}-preproc",
                if cfg.is_genesis_scale() { "genesis" } else { "dev" },
                cfg.preprocessing.label(),
            ),
            upstream: Upstream {
                repo: crate::UPSTREAM_REPO.to_string(),
                tag: crate::UPSTREAM_TAG.to_string(),
            },
            committee: CommitteeRecord {
                parties: cfg.parties,
                reconstruction_quorum: cfg.reconstruction_quorum(),
                session_threshold: cfg.session_threshold(),
                genesis_scale: cfg.is_genesis_scale(),
            },
            dkg: DkgRecord {
                params: cfg.params.name().to_string(),
                tag: cfg.tag.clone(),
                session_id,
                preprocessing: cfg.preprocessing.label().to_string(),
                preproc_seed: cfg.preproc_seed,
                wall_secs,
            },
            pk_g_sha256,
            roster_sha256: None, // set by the caller when a roster governs the run
            parties,
            environment: Environment {
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                created_unix: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            },
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)
            .with_context(|| format!("writing transcript to {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let json = fs::read_to_string(path)
            .with_context(|| format!("reading transcript from {}", path.display()))?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Level-1 verification: internal consistency of the transcript itself.
    pub fn verify_internal(&self) -> Result<()> {
        if self.schema != SCHEMA {
            bail!("unknown schema {:?} (expected {:?})", self.schema, SCHEMA);
        }
        let c = self.committee.parties;
        if self.parties.len() != c {
            bail!(
                "transcript has {} party records for committee size {}",
                self.parties.len(),
                c
            );
        }
        let expected_quorum = 3 * c / 4 + 1;
        if self.committee.reconstruction_quorum != expected_quorum {
            // An override is legal in tests but must be visible, not silent.
            eprintln!(
                "WARN: reconstruction quorum {} deviates from ⌊3c/4⌋+1 = {}",
                self.committee.reconstruction_quorum, expected_quorum
            );
        }
        if 3 * self.committee.session_threshold + 1 > c {
            bail!(
                "session threshold {} violates n ≥ 3t+1 for n = {}",
                self.committee.session_threshold,
                c
            );
        }
        if !is_hex_digest(&self.pk_g_sha256) {
            bail!("pk_g_sha256 is not a 64-hex-char SHA-256 digest");
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.parties {
            if p.role == 0 || p.role > c {
                bail!("party role {} out of range 1..={}", p.role, c);
            }
            if !seen.insert(p.role) {
                bail!("duplicate party role {}", p.role);
            }
            if !is_hex_digest(&p.share_commitment_sha256) {
                bail!("party {} share commitment is not a SHA-256 digest", p.role);
            }
        }
        Ok(())
    }

    /// Level-2 verification: recompute digests from a keys directory
    /// (only produced by dev runs that opted into writing key material).
    pub fn verify_against_keys(&self, keys_dir: &Path) -> Result<()> {
        self.verify_internal()?;

        let pk_path = keys_dir.join(PK_FILE);
        let pk_bytes = fs::read(&pk_path)
            .with_context(|| format!("reading {}", pk_path.display()))?;
        let got = sha256_hex(&pk_bytes);
        if got != self.pk_g_sha256 {
            bail!(
                "pk_G digest mismatch: transcript {} vs recomputed {}",
                self.pk_g_sha256,
                got
            );
        }

        for p in &self.parties {
            let share_path = keys_dir.join(share_file(p.role));
            if !share_path.exists() {
                // Shares are optional on disk; absence is not a failure.
                continue;
            }
            let bytes = fs::read(&share_path)
                .with_context(|| format!("reading {}", share_path.display()))?;
            let got = sha256_hex(&bytes);
            if got != p.share_commitment_sha256 {
                bail!(
                    "share commitment mismatch for party {}: transcript {} vs recomputed {}",
                    p.role,
                    p.share_commitment_sha256,
                    got
                );
            }
        }
        Ok(())
    }
}

fn is_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CommitteeConfig;

    fn dummy_transcript() -> Transcript {
        let cfg = CommitteeConfig::default();
        let parties = (1..=cfg.parties)
            .map(|role| PartyRecord {
                role,
                share_commitment_sha256: sha256_hex(format!("share-{role}").as_bytes()),
            })
            .collect();
        Transcript::build(&cfg, 1, sha256_hex(b"pk"), parties, None)
    }

    #[test]
    fn internal_verification_passes_and_catches_tampering() {
        let t = dummy_transcript();
        t.verify_internal().unwrap();

        let mut bad = t.clone();
        bad.parties.pop();
        assert!(bad.verify_internal().is_err(), "missing party record");

        let mut bad = t.clone();
        bad.pk_g_sha256 = "nope".into();
        assert!(bad.verify_internal().is_err(), "malformed digest");

        let mut bad = t;
        bad.parties[0].role = bad.parties[1].role;
        assert!(bad.verify_internal().is_err(), "duplicate role");
    }

    #[test]
    fn keys_dir_verification_detects_pk_swap() {
        let t = dummy_transcript();
        let dir = std::env::temp_dir().join(format!("celar-kms-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(PK_FILE), b"pk").unwrap();
        t.verify_against_keys(&dir).unwrap();

        std::fs::write(dir.join(PK_FILE), b"different pk").unwrap();
        assert!(t.verify_against_keys(&dir).is_err(), "pk swap must fail");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
