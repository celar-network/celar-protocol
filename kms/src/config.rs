//! Committee configuration — party count from config (onboarding §4, B1).
//!
//! Two thresholds are deliberately distinct (whitepaper §7.1 mapping,
//! reconstruction quorum vs robustness bound — the v0.9.10 disclosure):
//!
//! - `reconstruction_quorum` — Celar's t = ⌊3c/4⌋+1 (§7.7 genesis rule;
//!   79 at c=100 as the DESIGN TARGET). The number of partials a requester
//!   must combine, and the quorum the servability/combination layer enforces.
//!   NOTE (v0.9.22): production ceremonies under the current preprocessing
//!   engine deploy a threshold of 24 at c=100 — 25 seats suffice to
//!   reconstruct. 79 is not yet what is deployed; see whitepaper §7.1 for
//!   both figures and the path between them.
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

/// Hard ceiling on committee size imposed by the **sharing domain**, not by policy.
///
/// Each party's evaluation point is embedded in an *exceptional sequence* with
/// exactly `2^EXTENSION_DEGREE` elements, and index 0 is reserved for the secret,
/// so at most `2^EXTENSION_DEGREE - 1` parties can hold a share. Exceeding it fails
/// deep inside the algebra layer ("Value {idx} is too large to be embedded!"), a
/// long way from the configuration that caused it — which is why it is checked here.
pub const MAX_PARTIES: usize = (1 << crate::EXTENSION_DEGREE) - 1;

// Compile-time consistency between policy and algebra.
//
// This assertion exists because the two disagreed in shipped code and nothing
// noticed. Until 2026-08-20 `EXTENSION_DEGREE` was 4, giving MAX_PARTIES = 15,
// while `committee.rs` refused any committee below GENESIS_MIN = 30 — so **no
// committee size satisfied both**, and every "genesis-scale" test we had passed
// because it exercised the roster rules rather than an actual sharing at that size.
// Found while answering E18; filed as W33.
//
// A runtime check alone would have been the weaker fix: it only fires if someone
// runs a genesis-scale ceremony, which is exactly the thing that had never been run.
const _: () = assert!(
    GENESIS_MAX <= MAX_PARTIES,
    "EXTENSION_DEGREE is too small for the §7.7 genesis committee range: no \
     committee size satisfies both GENESIS_MIN..=GENESIS_MAX and the sharing \
     domain's 2^EXTENSION_DEGREE - 1 party ceiling. Raise EXTENSION_DEGREE \
     (upstream ships degrees 3-8) and re-measure — every ring element widens."
);

/// Which offline phase feeds the DKG (B1 hardening H1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PreprocMode {
    /// `DummyPreprocessing` — fast, NOT cryptographic. Skeleton/dev only.
    #[default]
    Dummy,
    /// `SecureSmallPreprocessing` — the real MPC offline phase (triples +
    /// randomness via sync reliable broadcast). **PRSS-based and hard-capped
    /// at `binom(n,t) ≤ 2047`, so it cannot reach genesis scale** —
    /// `binom(30,9) ≈ 14.3M` is refused. Real, small committees only.
    Secure,
    /// `SecureLargePreprocessing` — the real large-session offline phase
    /// (VSS + coinflip + single/double sharing; no PRSS, no party-count
    /// cap; flooding masks carry no `binom` factor). **This is what a
    /// genesis ceremony must run.** Caveats, stated because they matter:
    /// upstream ships this path tested to n=13 but their own production
    /// server never invokes it — we are its first production consumer, so
    /// the cross-party pk_G equality check is load-bearing here. And the
    /// corruption bound is **t < n/4** (enforced in `validate()` as a
    /// safety interlock, not a convenience): beyond it, reconstruction can
    /// be steered to a silently wrong result — the vendor declined the
    /// dispute-resolution extension that would make it fail closed.
    SecureLarge,
}

impl PreprocMode {
    pub fn label(&self) -> &'static str {
        match self {
            PreprocMode::Dummy => "dummy",
            PreprocMode::Secure => "secure-small",
            PreprocMode::SecureLarge => "secure-large",
        }
    }
}

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
    /// Offline phase: dummy (dev) or secure (the real MPC offline phase).
    #[serde(default)]
    pub preprocessing: PreprocMode,
    /// Seed for the dummy preprocessing (dummy mode only; recorded in the
    /// transcript so a run is reproducible).
    pub preproc_seed: u64,
    /// Offline-phase chunk size for the secure-large path: triples/randoms
    /// generated per sub-protocol run, accumulated into the base store.
    /// Trades memory against rounds — upstream never exceeds 10 in its own
    /// tests; a monolithic batch fails inside robust reconstruction. Peak
    /// RSS falls with smaller chunks; wall clock rises with the extra
    /// VSS/broadcast rounds. Recorded in the transcript environment.
    #[serde(default = "default_preproc_chunk")]
    pub preproc_chunk: usize,
}

fn default_preproc_chunk() -> usize {
    // Measured (c=5, test params, one machine, single batch of runs):
    // chunk 128 → 720 s, 512 → 439 s, 2048 → 332 s, 8192 → 303 s, with peak
    // RSS FLAT (~10.1–10.5 GiB) across the whole range — the floor is the
    // accumulated total material, not the chunk. So chunk size is a
    // wall-clock knob with a correctness cliff somewhere above 8192 (the
    // monolithic batch fails in robust reconstruction); 2048 takes most of
    // the win while staying 4× below the largest probed-safe value.
    2048
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            parties: 4,
            reconstruction_quorum: None,
            session_threshold: None,
            tag: "celar-genesis-dev".to_string(),
            params: ParamsChoice::Test,
            preprocessing: PreprocMode::default(),
            preproc_seed: 42,
            preproc_chunk: default_preproc_chunk(),
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
        // ⛔ SAFETY INTERLOCK — do not weaken to a warning, ever.
        //
        // The large-session offline path robust-opens DEGREE-2t values, so
        // it requires n ≥ 4t + 1 — a stricter corruption bound (t < n/4)
        // than the classic t < n/3 the session-threshold default assumes.
        // Upstream's own test committees for this path are exactly (5,1),
        // (9,2), (13,3).
        //
        // Why refusal is the only acceptable behaviour: the vendor
        // DELIBERATELY DECLINED the dispute-resolution extension for this
        // protocol (eprint 2025/699, p.4 §2.1 — "relatively complex, and so
        // we decided not to pursue this extension"), so reconstruction is
        // error-corrected degree-2t opening with NO post-reconstruction
        // commitment cross-check. Beyond the bound, a malicious excess
        // corruptor can steer an opening into a different codeword's
        // decoding sphere: the failure mode is SILENTLY INCORRECT OUTPUT —
        // a bad key that looks like a good one — not a detectable abort.
        // In the honest-but-misconfigured case the symptom is merely
        // "Could not reconstruct the sharing" deep in the library; in the
        // adversarial case there is no symptom at all. This check is the
        // only thing standing between a misconfigured ceremony and a
        // silently bad key.
        if self.preprocessing == PreprocMode::SecureLarge
            && self.parties <= 4 * self.session_threshold()
        {
            bail!(
                "secure-large preprocessing requires parties ≥ 4·t_session + 1: \
                 got c={} with t_session={} (need c ≥ {}). Either lower \
                 session_threshold explicitly (large-path corruption bound is \
                 t < n/4, not n/3 — e.g. t ≤ 7 at c=30, t ≤ 24 at c=100) or \
                 grow the committee. This bound is a safety interlock: beyond \
                 it, reconstruction can be steered to a silently wrong result \
                 rather than an abort.",
                self.parties,
                self.session_threshold(),
                4 * self.session_threshold() + 1
            );
        }
        if self.parties > MAX_PARTIES {
            bail!(
                "committee size {} exceeds the sharing domain ceiling of {} parties: \
                 EXTENSION_DEGREE = {} yields 2^{} exceptional points and index 0 is \
                 reserved for the secret. This is an algebra limit, not a policy one — \
                 raise EXTENSION_DEGREE (upstream ships degrees 3-8) and re-measure, \
                 since every ring element widens with it.",
                self.parties,
                MAX_PARTIES,
                crate::EXTENSION_DEGREE,
                crate::EXTENSION_DEGREE
            );
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
