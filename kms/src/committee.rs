//! Permissioned committee mode (whitepaper §7.7, genesis).
//!
//! At genesis the committee is not stake-sampled — it is a **vetted roster**:
//! c ∈ [30, 50] named members, reconstruction quorum t = ⌊3c/4⌋+1, fixed for
//! the epoch. This module makes that roster a first-class artifact:
//!
//! - `CommitteeRoster` — the vetted list (org, dial host/port, MPC identity,
//!   **CA-cert digest pin** per member) with §7.7 validation;
//! - `roster.digest()` — a canonical SHA-256 the ceremony artifacts commit
//!   to, so a transcript proves not just that *some* c parties ran a DKG but
//!   that *this vetted committee* did;
//! - mode-aware validation: `PermissionedGenesis` refuses dev-scale
//!   committees, threshold overrides, and dummy preprocessing.
//!
//! The permissionless §7.7 (stake-weighted VRF, staggered terms, eviction) is
//! Phase 2 and deliberately NOT modelled here.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{CommitteeConfig, ParamsChoice, PreprocMode, GENESIS_MAX, GENESIS_MIN};
use crate::transcript::sha256_hex;

/// How the committee was constituted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CommitteeMode {
    /// Development committee: any size ≥ 2, overrides allowed, dummy
    /// preprocessing allowed. NEVER a launch configuration.
    #[default]
    Dev,
    /// §7.7 genesis: vetted roster, c ∈ [30,50], t = ⌊3c/4⌋+1 fixed,
    /// secure preprocessing required.
    PermissionedGenesis,
}

/// One vetted committee member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterMember {
    /// One-based role index (stable for the epoch).
    pub role: usize,
    /// The vetted organisation (§7.7: named orgs across jurisdictions —
    /// jurisdiction diversity is tracked at recruitment, recorded here).
    pub org: String,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    /// Dial address of the member's KMS node.
    pub host: String,
    pub port: u16,
    /// MPC identity = TLS cert subject (see node.rs H2 findings).
    pub mpc_identity: String,
    /// SHA-256 of the member's CA certificate file (PEM bytes) — the
    /// permissioned trust pin. Nodes refuse ceremonies whose trust roots
    /// don't match the roster.
    pub ca_cert_sha256: String,
}

/// The vetted committee for one epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeRoster {
    pub schema: String,
    pub mode: CommitteeMode,
    /// Keyset tag the ceremony will bind (must match the committee config).
    pub tag: String,
    pub params: ParamsChoice,
    pub members: Vec<RosterMember>,
}

pub const ROSTER_SCHEMA: &str = "celar-committee-roster/v0";

impl CommitteeRoster {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading roster {}", path.display()))?;
        let r: Self = serde_json::from_str(&raw)?;
        r.validate()?;
        Ok(r)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing roster {}", path.display()))?;
        Ok(())
    }

    /// Canonical digest the ceremony artifacts commit to. Canonical form =
    /// compact JSON of the roster with members sorted by role (serde
    /// preserves struct field order, so this is deterministic).
    pub fn digest(&self) -> Result<String> {
        let mut sorted = self.clone();
        sorted.members.sort_by_key(|m| m.role);
        Ok(sha256_hex(serde_json::to_string(&sorted)?.as_bytes()))
    }

    pub fn parties(&self) -> usize {
        self.members.len()
    }

    /// §7.7 validation. Dev mode gets structural checks only; genesis mode
    /// gets the constitutional rules.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ROSTER_SCHEMA {
            bail!("unknown roster schema {:?}", self.schema);
        }
        let c = self.members.len();
        if c < 2 {
            bail!("roster needs at least 2 members");
        }

        // Structural: roles are exactly 1..=c, identities/pins unique.
        let mut roles: Vec<usize> = self.members.iter().map(|m| m.role).collect();
        roles.sort_unstable();
        if roles != (1..=c).collect::<Vec<_>>() {
            bail!("member roles must be exactly 1..={c} with no gaps or duplicates");
        }
        let mut idents = std::collections::HashSet::new();
        let mut pins = std::collections::HashSet::new();
        let mut endpoints = std::collections::HashSet::new();
        for m in &self.members {
            if m.org.trim().is_empty() {
                bail!("member {} has an empty org", m.role);
            }
            if !idents.insert(&m.mpc_identity) {
                bail!("duplicate MPC identity {:?}", m.mpc_identity);
            }
            if m.ca_cert_sha256.len() != 64
                || !m.ca_cert_sha256.chars().all(|ch| ch.is_ascii_hexdigit())
            {
                bail!("member {}: ca_cert_sha256 is not a SHA-256 hex digest", m.role);
            }
            if !pins.insert(&m.ca_cert_sha256) {
                bail!(
                    "duplicate CA pin for member {} — one CA per member, or a \
                     single compromised CA speaks for several seats",
                    m.role
                );
            }
            if !endpoints.insert((m.host.clone(), m.port)) {
                bail!("duplicate endpoint {}:{}", m.host, m.port);
            }
        }

        // Constitutional (genesis only).
        if self.mode == CommitteeMode::PermissionedGenesis {
            if !(GENESIS_MIN..=GENESIS_MAX).contains(&c) {
                bail!(
                    "§7.7 genesis committee must have {}..={} members (got {c})",
                    GENESIS_MIN,
                    GENESIS_MAX
                );
            }
            // Distinct orgs — one organisation must not hold multiple seats.
            let mut orgs = std::collections::HashSet::new();
            for m in &self.members {
                if !orgs.insert(m.org.trim().to_ascii_lowercase()) {
                    bail!(
                        "org {:?} holds more than one genesis seat — one seat per \
                         vetted org (§7.7)",
                        m.org
                    );
                }
            }
        }
        Ok(())
    }

    /// The §7.7 reconstruction quorum for this roster: t = ⌊3c/4⌋+1.
    /// Not configurable in genesis mode — the formula IS the rule.
    pub fn reconstruction_quorum(&self) -> usize {
        3 * self.parties() / 4 + 1
    }

    /// Derive the CommitteeConfig this roster mandates.
    pub fn committee_config(&self) -> Result<CommitteeConfig> {
        let cfg = CommitteeConfig {
            parties: self.parties(),
            reconstruction_quorum: None, // formula-derived; overrides refused below
            session_threshold: None,
            tag: self.tag.clone(),
            params: self.params,
            preprocessing: match self.mode {
                // Genesis ceremonies never run on dummy preprocessing.
                //
                // ⚠️ KNOWN-WRONG mapping, kept deliberately for one more
                // unit: `Secure` is the PRSS path, hard-capped at
                // binom(n,t) ≤ 2047 — it CANNOT run at genesis scale
                // (binom(30,9) ≈ 14.3M). The correct target is
                // `SecureLarge`, but that requires t ≤ ⌊(c−1)/4⌋ (the n/4
                // corruption bound), so switching it changes what
                // session_threshold this function must derive and what
                // the roster tests assert. Scheduled as its own change,
                // not smuggled into a compile fix.
                CommitteeMode::PermissionedGenesis => PreprocMode::Secure,
                CommitteeMode::Dev => PreprocMode::Secure,
            },
            preproc_seed: 42,
            preproc_chunk: 512,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Check a set of CA files (paths) against the roster pins: the digests
    /// must match the pinned set EXACTLY — no missing, no extra trust roots.
    pub fn verify_ca_set(&self, ca_paths: &[String]) -> Result<()> {
        let mut found = std::collections::HashSet::new();
        for path in ca_paths {
            let bytes = fs::read(path)
                .with_context(|| format!("reading CA file {path}"))?;
            found.insert(sha256_hex(&bytes));
        }
        let pinned: std::collections::HashSet<String> = self
            .members
            .iter()
            .map(|m| m.ca_cert_sha256.clone())
            .collect();
        if found != pinned {
            let extra: Vec<_> = found.difference(&pinned).cloned().collect();
            let missing: Vec<_> = pinned.difference(&found).cloned().collect();
            bail!(
                "trust roots do not match the roster pins — a node must trust \
                 exactly the vetted committee's CAs.\n  unpinned CAs present: {:?}\n  pinned CAs missing: {:?}",
                extra,
                missing
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(role: usize, org: &str) -> RosterMember {
        RosterMember {
            role,
            org: org.to_string(),
            jurisdiction: Some("XX".into()),
            host: format!("core1.party{role}"),
            port: 51000 + role as u16,
            mpc_identity: format!("core1.party{role}"),
            ca_cert_sha256: sha256_hex(format!("ca-{role}").as_bytes()),
        }
    }

    fn roster(mode: CommitteeMode, c: usize) -> CommitteeRoster {
        CommitteeRoster {
            schema: ROSTER_SCHEMA.to_string(),
            mode,
            tag: "celar-genesis".into(),
            params: ParamsChoice::Test,
            members: (1..=c).map(|i| member(i, &format!("org-{i}"))).collect(),
        }
    }

    #[test]
    fn genesis_rules() {
        // c=30 valid, quorum 23 — the onboarding doc's own constant.
        let r = roster(CommitteeMode::PermissionedGenesis, 30);
        r.validate().unwrap();
        assert_eq!(r.reconstruction_quorum(), 23);

        // c=50 valid; c=29 and c=51 refused.
        roster(CommitteeMode::PermissionedGenesis, 50).validate().unwrap();
        assert!(roster(CommitteeMode::PermissionedGenesis, 29).validate().is_err());
        assert!(roster(CommitteeMode::PermissionedGenesis, 51).validate().is_err());

        // Same size is fine in dev mode.
        roster(CommitteeMode::Dev, 4).validate().unwrap();
    }

    #[test]
    fn one_seat_per_org_in_genesis() {
        let mut r = roster(CommitteeMode::PermissionedGenesis, 30);
        r.members[1].org = r.members[0].org.clone();
        assert!(r.validate().is_err(), "duplicate org must be refused");

        // …but tolerated in dev mode.
        let mut d = roster(CommitteeMode::Dev, 4);
        d.members[1].org = d.members[0].org.clone();
        d.validate().unwrap();
    }

    #[test]
    fn structural_rules() {
        let mut r = roster(CommitteeMode::Dev, 4);
        r.members[2].role = 2; // duplicate role
        assert!(r.validate().is_err());

        let mut r = roster(CommitteeMode::Dev, 4);
        r.members[3].ca_cert_sha256 = r.members[0].ca_cert_sha256.clone();
        assert!(r.validate().is_err(), "shared CA pin must be refused");

        let mut r = roster(CommitteeMode::Dev, 4);
        r.members[3].mpc_identity = r.members[0].mpc_identity.clone();
        assert!(r.validate().is_err(), "shared MPC identity must be refused");
    }

    #[test]
    fn digest_is_order_invariant_and_content_sensitive() {
        let r1 = roster(CommitteeMode::Dev, 4);
        let mut r2 = r1.clone();
        r2.members.reverse();
        assert_eq!(r1.digest().unwrap(), r2.digest().unwrap());

        let mut r3 = r1.clone();
        r3.members[0].org = "someone-else".into();
        assert_ne!(r1.digest().unwrap(), r3.digest().unwrap());
    }

    #[test]
    fn derived_config_matches_formula() {
        let r = roster(CommitteeMode::PermissionedGenesis, 32);
        let cfg = r.committee_config().unwrap();
        assert_eq!(cfg.parties, 32);
        assert_eq!(cfg.reconstruction_quorum(), 25); // ⌊96/4⌋+1
        assert_eq!(cfg.preprocessing, PreprocMode::Secure);
    }
}
