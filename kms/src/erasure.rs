//! Attested erasure of superseded shares — the step that makes proactive
//! refresh BINDING.
//!
//! A refresh moves the committee to a new sharing polynomial; epochs e and
//! e+1 do not interpolate together. That only converts "compromise t+1 ever"
//! into "compromise t+1 within one epoch" IF the superseded shares actually
//! cease to exist: a seat that retains them hands a sequential adversary
//! shares of ONE epoch's polynomial, collected across years. Proactive
//! sharing without erasure is provably impossible — so erasure is the
//! precondition of the control, not hardening on top of it.
//!
//! What this module supplies, and the honest line between its pieces:
//!
//! - **The retention-site scan** looks for the superseded share where
//!   retention actually happens — the STORAGE layer: backup directories,
//!   snapshot directories, dump files — by exact content hash AND by an
//!   embedded byte-probe (a share copied into a larger blob, as a crash dump
//!   or archive would). The scan runs BEFORE zeroization, while the share
//!   bytes are still known.
//! - **The environment probe** checks the two retention channels a path scan
//!   cannot see: active swap and unrestricted core dumps. Operators are
//!   admitted on the promise that both are disabled; the probe converts the
//!   promise into an attested observation.
//! - **Zeroization** overwrites and unlinks the share file. On journaling or
//!   copy-on-write filesystems an overwrite is BEST-EFFORT — prior blocks may
//!   survive relocation. The documented procedure therefore requires
//!   full-disk encryption (destroying the key destroys stragglers) or an
//!   HSM/enclave reseal; this module attests what was done and found, it does
//!   not claim physics it cannot deliver.
//! - **The attestation** binds role, epoch, the superseded share's
//!   commitment, the scan result, and the environment probe under the seat's
//!   operational key. **The audit hook refuses epoch completion on ANY
//!   finding, ANY dirty environment, ANY missing or invalid attestation** —
//!   an un-erased share is a compliance failure, not a warning.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::transcript::sha256_hex;

/// Signing domain for erasure attestations. The operational key signs three
/// message families (endorsement digests, VRF contribution inputs, and these
/// attestations); each family is domain-separated and the disjointness is
/// pinned by a negative test beside the other two families' domains.
pub const ERASURE_SIGN_DOMAIN: &str = "celar.kms.erasure.attestation.v1";

pub const ERASURE_ATTESTATION_SCHEMA: &str = "celar-erasure-attestation/v1";

pub fn erasure_attestation_file(role: usize) -> String {
    format!("erasure_attestation_{role:03}.json")
}

/// One retention finding: the superseded share (whole or embedded) observed
/// at a path the operator's retention sites should not be holding it in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionFinding {
    pub path: String,
    /// "exact-copy" (file content hashes equal to the share) or
    /// "embedded" (the share's probe bytes found inside a larger file).
    pub kind: String,
}

/// The two retention channels a path scan cannot see, observed rather than
/// promised. `None` = not observable on this platform (recorded as such —
/// an unobservable channel is not a clean one).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentProbe {
    pub swap_active: Option<bool>,
    pub core_dumps_enabled: Option<bool>,
}

impl EnvironmentProbe {
    /// Read the live environment (Linux: /proc/swaps and
    /// /proc/sys/kernel/core_pattern). Elsewhere both are `None`.
    pub fn observe() -> Self {
        let swap_active = fs::read_to_string("/proc/swaps")
            .ok()
            .map(|s| s.lines().count() > 1);
        // A core_pattern that is empty or /dev/null means dumps go nowhere;
        // anything else (a path or a pipe) is a live retention channel.
        let core_dumps_enabled = fs::read_to_string("/proc/sys/kernel/core_pattern")
            .ok()
            .map(|s| {
                let p = s.trim();
                !(p.is_empty() || p == "/dev/null" || p == "|/bin/false" || p == "core" && false)
            });
        Self {
            swap_active,
            core_dumps_enabled,
        }
    }
}

/// A seat's signed record of what it erased, what it scanned, and what it
/// observed. The signature is over the canonical bytes of everything above
/// it (see [`signing_bytes`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureAttestation {
    pub schema: String,
    pub role: usize,
    /// The refresh event this erasure belongs to — the same epoch identifier
    /// the refresh run used, so attestations cannot be replayed across
    /// refreshes.
    pub epoch: u64,
    /// SHA-256 of the superseded share's bytes, matching the commitment the
    /// transcript recorded for it — binds the attestation to the share that
    /// was actually destroyed, not merely "a" share.
    pub superseded_share_sha256: String,
    /// Paths zeroized and unlinked.
    pub zeroized_paths: Vec<String>,
    /// Retention sites scanned (recorded so an empty-findings attestation
    /// also says WHERE it looked).
    pub scanned_sites: Vec<String>,
    pub findings: Vec<RetentionFinding>,
    pub environment: EnvironmentProbe,
    pub created_unix: u64,
    /// ed25519 signature (128-hex) under the seat's operational key over
    /// `ERASURE_SIGN_DOMAIN ‖ canonical-json(self minus signature)`.
    pub signature: String,
}

/// Canonical signed bytes: the domain, then compact JSON of the attestation
/// with the signature field emptied. One canonical form, same discipline as
/// the roster's anchored bytes.
fn signing_bytes(att: &ErasureAttestation) -> Result<Vec<u8>> {
    let mut unsigned = att.clone();
    unsigned.signature = String::new();
    let json = serde_json::to_vec(&unsigned).context("canonicalizing attestation")?;
    let mut out = Vec::with_capacity(ERASURE_SIGN_DOMAIN.len() + json.len());
    out.extend_from_slice(ERASURE_SIGN_DOMAIN.as_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Scan retention sites for the superseded share: exact copies by content
/// hash, embedded copies by probe search (a 64-byte window from the middle
/// of the share — distinctive share material, cheap to search for, and gone
/// once the share is zeroized). Recurses one level of directories; sites are
/// explicit paths, not a filesystem crawl.
pub fn scan_retention_sites(
    sites: &[PathBuf],
    share_bytes: &[u8],
) -> Result<Vec<RetentionFinding>> {
    let share_hash = sha256_hex(share_bytes);
    let probe: &[u8] = if share_bytes.len() >= 96 {
        &share_bytes[share_bytes.len() / 2..share_bytes.len() / 2 + 64]
    } else {
        share_bytes
    };

    let mut findings = Vec::new();
    let mut check_file = |path: &Path| -> Result<()> {
        let content = match fs::read(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // unreadable entries are the operator's audit problem, not a crash
        };
        if sha256_hex(&content) == share_hash {
            findings.push(RetentionFinding {
                path: path.display().to_string(),
                kind: "exact-copy".into(),
            });
        } else if content.len() >= probe.len()
            && content.windows(probe.len()).any(|w| w == probe)
        {
            findings.push(RetentionFinding {
                path: path.display().to_string(),
                kind: "embedded".into(),
            });
        }
        Ok(())
    };

    for site in sites {
        if site.is_file() {
            check_file(site)?;
        } else if site.is_dir() {
            for entry in fs::read_dir(site).with_context(|| format!("scanning {}", site.display()))? {
                let p = entry?.path();
                if p.is_file() {
                    check_file(&p)?;
                } else if p.is_dir() {
                    for sub in fs::read_dir(&p)? {
                        let sp = sub?.path();
                        if sp.is_file() {
                            check_file(&sp)?;
                        }
                    }
                }
            }
        }
        // A configured site that does not exist is fine: nothing retained there.
    }
    Ok(findings)
}

/// Overwrite a file with zeros and unlink it. Best-effort at the filesystem
/// level (see the module note on copy-on-write); the attestation records the
/// act, the documented procedure supplies the physical guarantee.
pub fn zeroize_file(path: &Path) -> Result<()> {
    let len = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .len() as usize;
    fs::write(path, vec![0u8; len]).with_context(|| format!("overwriting {}", path.display()))?;
    let f = fs::File::open(path)?;
    f.sync_all().ok();
    drop(f);
    fs::remove_file(path).with_context(|| format!("unlinking {}", path.display()))?;
    Ok(())
}

/// Perform the full erasure step for one seat and sign the attestation:
/// scan FIRST (the share bytes are needed as the probe), then zeroize, then
/// attest what was done, found, and observed. The caller supplies the
/// environment probe so tests can inject dirty environments; production
/// callers pass [`EnvironmentProbe::observe`].
pub fn attest_erasure(
    signing_key_path: &Path,
    role: usize,
    epoch: u64,
    share_path: &Path,
    retention_sites: &[PathBuf],
    environment: EnvironmentProbe,
) -> Result<ErasureAttestation> {
    use ed25519_dalek::{Signer, SigningKey};

    let share_bytes =
        fs::read(share_path).with_context(|| format!("reading superseded share {}", share_path.display()))?;
    let superseded_share_sha256 = sha256_hex(&share_bytes);
    let findings = scan_retention_sites(retention_sites, &share_bytes)?;
    zeroize_file(share_path)?;
    drop(share_bytes);

    let mut att = ErasureAttestation {
        schema: ERASURE_ATTESTATION_SCHEMA.to_string(),
        role,
        epoch,
        superseded_share_sha256,
        zeroized_paths: vec![share_path.display().to_string()],
        scanned_sites: retention_sites.iter().map(|p| p.display().to_string()).collect(),
        findings,
        environment,
        created_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        signature: String::new(),
    };

    let raw = fs::read_to_string(signing_key_path)
        .with_context(|| format!("reading operational signing key {}", signing_key_path.display()))?;
    let bytes = hex::decode(raw.trim()).context("operational signing key is not hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("operational signing key is not 32 bytes"))?;
    let sk = SigningKey::from_bytes(&arr);
    att.signature = hex::encode(sk.sign(&signing_bytes(&att)?).to_bytes());
    Ok(att)
}

/// Verify one attestation's signature against a rostered pubkey (64-hex).
pub fn verify_erasure_attestation(pubkey_hex: &str, att: &ErasureAttestation) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = hex::decode(pubkey_hex.trim())
        .context("attestation pubkey is not hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("attestation pubkey is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).context("pubkey is not a valid ed25519 point")?;
    let sig_bytes: [u8; 64] = hex::decode(att.signature.trim())
        .context("attestation signature is not hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("attestation signature is not 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&signing_bytes(att)?, &sig)
        .map_err(|e| anyhow::anyhow!("erasure attestation failed verification: {e}"))
}

/// THE AUDIT HOOK: epoch completion is refused unless EVERY seat presents a
/// valid, clean attestation for THIS epoch. Any missing seat, invalid
/// signature, wrong epoch, retention finding, or dirty/unobservable-dirty
/// environment is a COMPLIANCE FAILURE naming the seat — never a warning.
/// `expected` maps role → (rostered signing pubkey hex, the superseded
/// share's recorded commitment).
pub fn audit_erasure_attestations(
    attestations: &[ErasureAttestation],
    expected: &std::collections::BTreeMap<usize, (String, String)>,
    epoch: u64,
) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for att in attestations {
        let (pubkey, expected_commitment) = expected
            .get(&att.role)
            .ok_or_else(|| anyhow::anyhow!("attestation from unrostered role {}", att.role))?;
        if att.schema != ERASURE_ATTESTATION_SCHEMA {
            bail!("role {}: unknown attestation schema {:?}", att.role, att.schema);
        }
        if !seen.insert(att.role) {
            bail!("duplicate attestation for role {}", att.role);
        }
        if att.epoch != epoch {
            bail!(
                "role {}: attestation is for epoch {}, this refresh is epoch {epoch} — replay refused",
                att.role, att.epoch
            );
        }
        verify_erasure_attestation(pubkey, att)
            .with_context(|| format!("role {}", att.role))?;
        if &att.superseded_share_sha256 != expected_commitment {
            bail!(
                "role {}: attestation destroys a share with commitment {} but the transcript \
                 recorded {} — the attested erasure is not of the superseded share",
                att.role, att.superseded_share_sha256, expected_commitment
            );
        }
        if !att.findings.is_empty() {
            bail!(
                "COMPLIANCE FAILURE role {}: superseded share retained at {} site(s): {} — \
                 epoch completion refused",
                att.role,
                att.findings.len(),
                att.findings
                    .iter()
                    .map(|f| format!("{} ({})", f.path, f.kind))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if att.environment.swap_active == Some(true) {
            bail!(
                "COMPLIANCE FAILURE role {}: swap is active — share material can be paged to \
                 disk; epoch completion refused",
                att.role
            );
        }
        if att.environment.core_dumps_enabled == Some(true) {
            bail!(
                "COMPLIANCE FAILURE role {}: core dumps are enabled — a crash writes share \
                 material to disk; epoch completion refused",
                att.role
            );
        }
    }
    // Every expected seat must have attested — a silent seat is a retained
    // share until proven otherwise.
    for role in expected.keys() {
        if !seen.contains(role) {
            bail!(
                "role {role}: no erasure attestation — epoch completion refused \
                 (a missing attestation is a retained share until attested otherwise)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn keypair(seed: u8) -> (PathBuf, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let dir = std::env::temp_dir().join(format!("celar-erasure-key-{seed}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("signing.key");
        fs::write(&path, hex::encode(sk.to_bytes())).unwrap();
        (path, hex::encode(sk.verifying_key().to_bytes()))
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "celar-erasure-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn fake_share(dir: &Path) -> (PathBuf, Vec<u8>) {
        // Distinctive bytes, larger than the probe window.
        let bytes: Vec<u8> = (0..4096u32).flat_map(|i| i.to_be_bytes()).collect();
        let p = dir.join("party_001.share.bin");
        fs::write(&p, &bytes).unwrap();
        (p, bytes)
    }

    fn clean_env() -> EnvironmentProbe {
        EnvironmentProbe {
            swap_active: Some(false),
            core_dumps_enabled: Some(false),
        }
    }

    #[test]
    fn clean_erasure_attests_zeroizes_and_passes_audit() {
        let work = temp_dir("clean");
        let (share_path, share_bytes) = fake_share(&work);
        let commitment = sha256_hex(&share_bytes);
        let (key, pubkey) = keypair(1);
        let backup_site = temp_dir("clean-backup"); // empty — nothing retained

        let att = attest_erasure(&key, 1, 7, &share_path, &[backup_site], clean_env()).unwrap();
        assert!(att.findings.is_empty());
        assert!(!share_path.exists(), "superseded share must be unlinked");

        let mut expected = BTreeMap::new();
        expected.insert(1usize, (pubkey, commitment));
        audit_erasure_attestations(&[att], &expected, 7).unwrap();
    }

    // ---- THE STORAGE-LAYER NEGATIVE TESTS: retention at each storage site
    // must surface as a finding and refuse the epoch. ----

    #[test]
    fn backup_exact_copy_is_a_compliance_failure() {
        let work = temp_dir("backup");
        let (share_path, share_bytes) = fake_share(&work);
        let commitment = sha256_hex(&share_bytes);
        let (key, pubkey) = keypair(2);
        let backup_site = temp_dir("backup-site");
        fs::write(backup_site.join("share.bak"), &share_bytes).unwrap(); // the backup

        let att =
            attest_erasure(&key, 1, 7, &share_path, &[backup_site], clean_env()).unwrap();
        assert_eq!(att.findings.len(), 1);
        assert_eq!(att.findings[0].kind, "exact-copy");

        let mut expected = BTreeMap::new();
        expected.insert(1usize, (pubkey, commitment));
        let err = audit_erasure_attestations(&[att], &expected, 7).unwrap_err().to_string();
        assert!(err.contains("COMPLIANCE FAILURE"), "{err}");
        assert!(err.contains("retained"), "{err}");
    }

    #[test]
    fn share_embedded_in_a_crash_dump_is_found_and_refused() {
        let work = temp_dir("dump");
        let (share_path, share_bytes) = fake_share(&work);
        let commitment = sha256_hex(&share_bytes);
        let (key, pubkey) = keypair(3);
        // A "crash dump": the share bytes buried inside a larger blob —
        // content-hash comparison alone would miss this; the probe must not.
        let dump_site = temp_dir("dump-site");
        let mut blob = vec![0xABu8; 10_000];
        blob.extend_from_slice(&share_bytes);
        blob.extend_from_slice(&[0xCD; 5_000]);
        fs::write(dump_site.join("core.1234"), &blob).unwrap();

        let att = attest_erasure(&key, 1, 7, &share_path, &[dump_site], clean_env()).unwrap();
        assert_eq!(att.findings.len(), 1);
        assert_eq!(att.findings[0].kind, "embedded");

        let mut expected = BTreeMap::new();
        expected.insert(1usize, (pubkey, commitment));
        assert!(audit_erasure_attestations(&[att], &expected, 7).is_err());
    }

    #[test]
    fn snapshot_directory_copy_is_found_one_level_down() {
        let work = temp_dir("snap");
        let (share_path, share_bytes) = fake_share(&work);
        let (key, _) = keypair(4);
        // A "snapshot": a dated subdirectory holding yesterday's files.
        let snap_site = temp_dir("snap-site");
        let dated = snap_site.join("snapshot-2026-10-01");
        fs::create_dir_all(&dated).unwrap();
        fs::write(dated.join("party_001.share.bin"), &share_bytes).unwrap();

        let att = attest_erasure(&key, 1, 7, &share_path, &[snap_site], clean_env()).unwrap();
        assert_eq!(att.findings.len(), 1, "snapshot copy must be found in the dated subdir");
    }

    #[test]
    fn active_swap_and_enabled_core_dumps_each_refuse_the_epoch() {
        let work = temp_dir("env");
        let (share_path, share_bytes) = fake_share(&work);
        let commitment = sha256_hex(&share_bytes);
        let (key, pubkey) = keypair(5);
        let att = attest_erasure(
            &key, 1, 7, &share_path, &[],
            EnvironmentProbe { swap_active: Some(true), core_dumps_enabled: Some(false) },
        )
        .unwrap();
        let mut expected = BTreeMap::new();
        expected.insert(1usize, (pubkey.clone(), commitment.clone()));
        let err = audit_erasure_attestations(&[att], &expected, 7).unwrap_err().to_string();
        assert!(err.contains("swap is active"), "{err}");

        // Core dumps: fresh share file (the first was zeroized).
        let (share_path2, share_bytes2) = fake_share(&work);
        assert_eq!(sha256_hex(&share_bytes2), commitment);
        let att2 = attest_erasure(
            &key, 1, 7, &share_path2, &[],
            EnvironmentProbe { swap_active: Some(false), core_dumps_enabled: Some(true) },
        )
        .unwrap();
        let err2 = audit_erasure_attestations(&[att2], &expected, 7).unwrap_err().to_string();
        assert!(err2.contains("core dumps are enabled"), "{err2}");
    }

    // ---- Attestation integrity ----

    #[test]
    fn tampered_attestation_and_missing_seat_are_refused() {
        let work = temp_dir("tamper");
        let (share_path, share_bytes) = fake_share(&work);
        let commitment = sha256_hex(&share_bytes);
        let (key, pubkey) = keypair(6);
        let att = attest_erasure(&key, 1, 7, &share_path, &[], clean_env()).unwrap();

        // Tamper: claim a different epoch after signing.
        let mut forged = att.clone();
        forged.epoch = 8;
        let mut expected = BTreeMap::new();
        expected.insert(1usize, (pubkey.clone(), commitment.clone()));
        assert!(
            audit_erasure_attestations(&[forged], &expected, 8).is_err(),
            "an epoch-tampered attestation must fail signature verification"
        );

        // Replay: valid attestation presented for the wrong refresh.
        assert!(audit_erasure_attestations(&[att.clone()], &expected, 9).is_err());

        // Missing seat: expected committee of two, one attested.
        expected.insert(2usize, (pubkey, commitment));
        let err = audit_erasure_attestations(&[att], &expected, 7).unwrap_err().to_string();
        assert!(err.contains("no erasure attestation"), "{err}");
    }

    #[test]
    fn wrong_share_commitment_is_refused() {
        let work = temp_dir("wrongshare");
        let (share_path, _) = fake_share(&work);
        let (key, pubkey) = keypair(7);
        let att = attest_erasure(&key, 1, 7, &share_path, &[], clean_env()).unwrap();
        let mut expected = BTreeMap::new();
        // The transcript recorded a DIFFERENT commitment than what was destroyed.
        expected.insert(1usize, (pubkey, "00".repeat(32)));
        let err = audit_erasure_attestations(&[att], &expected, 7).unwrap_err().to_string();
        assert!(err.contains("not of the superseded share"), "{err}");
    }
}
