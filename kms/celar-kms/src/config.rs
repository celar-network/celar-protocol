//! Committee configuration — party count from config (onboarding §4, B1).
//!
//! Two thresholds are deliberately distinct (whitepaper §7.1 mapping,
//! reconstruction quorum vs robustness bound — the v0.9.10 disclosure):
//!
//! - `reconstruction_quorum` — Celar's t = ⌊3c/4⌋+1 (§7.7 genesis rule;
//!   79 at c=100). The number of partials a requester must combine, and the
//!   quorum the servability/combination layer enforces.
//! - `session_threshold` — the MPC corruption bound handed to the upstream
//!   protocol session (their tests run n=4/t=1, n=5/t=1). Defaults to
//!   ⌊(c−1)/3⌋, the classic robust-MPC bound.
//!
//! ⚠ OPEN SPEC QUESTION (routed to owner/spec via work orders, do not silently
//! "fix" here): how Celar's reconstruction quorum maps onto the upstream
//! sharing degree. If the Shamir degree follows `session_threshold`, then
//! degree+1 shares reconstruct — fewer than ⌊3c/4⌋+1. The whitepaper's §7.1
//! convention note is the seam; B1 proper must resolve the mapping before any
//! security claim is attached to the quorum number. The config carries both
//! numbers explicitly so the decision lands in one place.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Genesis (permissioned) committee size range, whitepaper §7.7.
pub const GENESIS_MIN: usize = 30;
pub const GENESIS_MAX: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParamsChoice {
    /// Upstream's fast test parameter set (PARAMS_TEST_BK_SNS). Dev only —
    /// NOT a production 𝒫_FHE; parameter selection is its own task.
    Test,
    /// NIST-submission P32 SnS parameters — closer to real cost, much slower.
    NistP32SnsFglwe,
}

impl ParamsChoice {
    pub fn name(&self) -> &'static str {
        match self {
            ParamsChoice::Test => "PARAMS_TEST_BK_SNS",
            ParamsChoice::NistP32SnsFglwe => "NIST_PARAMS_P32_SNS_FGLWE",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeConfig {
    /// Committee size c. Genesis range is 30–50; smaller values run as a
    /// dev profile and the transcript is marked accordingly.
    pub parties: usize,
    /// Override for t = ⌊3c/4⌋+1. Leave unset outside tests.
    #[serde(default)]
    pub reconstruction_quorum: Option<usize>,
    /// Override for the upstream session corruption bound. Leave unset
    /// outside tests.
    #[serde(default)]
    pub session_threshold: Option<usize>,
    /// Domain tag bound into the generated keyset (tfhe::Tag).
    pub tag: String,
    /// DKG parameter set.
    pub params: ParamsChoice,
    /// Seed for the dummy preprocessing (skeleton only; recorded in the
    /// transcript so a run is reproducible).
    pub preproc_seed: u64,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            parties: 4,
            reconstruction_quorum: None,
            session_threshold: None,
            tag: "celar-genesis-dev".to_string(),
            params: ParamsChoice::Test,
            preproc_seed: 42,
        }
    }
}

impl CommitteeConfig {
    /// t = ⌊3c/4⌋+1 (§7.7), unless explicitly overridden.
    pub fn reconstruction_quorum(&self) -> usize {
        self.reconstruction_quorum
            .unwrap_or(3 * self.parties / 4 + 1)
    }

    /// Upstream MPC corruption bound, default ⌊(c−1)/3⌋ (min 1).
    pub fn session_threshold(&self) -> usize {
        self.session_threshold
            .unwrap_or(((self.parties.saturating_sub(1)) / 3).max(1))
    }

    /// Whether c is in the §7.7 genesis range (vs a dev-profile run).
    pub fn is_genesis_scale(&self) -> bool {
        (GENESIS_MIN..=GENESIS_MAX).contains(&self.parties)
    }

    pub fn validate(&self) -> Result<()> {
        if self.parties < 2 {
            bail!("committee needs at least 2 parties (got {})", self.parties);
        }
        let t_r = self.reconstruction_quorum();
        if t_r > self.parties {
            bail!(
                "reconstruction quorum {} exceeds committee size {}",
                t_r,
                self.parties
            );
        }
        let t_s = self.session_threshold();
        if 3 * t_s + 1 > self.parties {
            bail!(
                "session threshold {} violates n ≥ 3t+1 for n = {}",
                t_s,
                self.parties
            );
        }
        if self.tag.is_empty() {
            bail!("tag must not be empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_quorum_rule() {
        // §7.7: t = ⌊3c/4⌋+1 — t=23 at c=30 (onboarding doc's own example).
        let cfg = CommitteeConfig {
            parties: 30,
            ..Default::default()
        };
        assert_eq!(cfg.reconstruction_quorum(), 23);
        assert!(cfg.is_genesis_scale());

        // and 79 at c=100 (permissionless scale).
        let cfg = CommitteeConfig {
            parties: 100,
            ..Default::default()
        };
        assert_eq!(cfg.reconstruction_quorum(), 76);
        // NOTE: ⌊3·100/4⌋+1 = 76, not 79. The whitepaper's 79-of-100 is the
        // permissionless-scale constant, not this formula — the formula is the
        // §7.7 GENESIS rule. Keeping this assertion honest rather than forcing
        // 79 documents exactly the seam flagged in the module docs.
    }

    #[test]
    fn dev_profile_validates() {
        let cfg = CommitteeConfig::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.parties, 4);
        assert_eq!(cfg.session_threshold(), 1);
        assert!(!cfg.is_genesis_scale());
    }

    #[test]
    fn session_threshold_bound_enforced() {
        let cfg = CommitteeConfig {
            parties: 4,
            session_threshold: Some(2), // 3·2+1 = 7 > 4
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
