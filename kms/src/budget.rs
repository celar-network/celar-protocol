//! Decryption-budget accounting (§7.2 "Query budget" and
//! "Decryption-oracle threat model and budget granularity", whitepaper
//! v0.9.15 — both paragraphs are PUBLISHED normative text, not parked).
//!
//! Why a budget exists at all: the flooding guarantee composes **additively**.
//! After Q decryption-bearing operations under one key epoch the total
//! simulation distance is ≤ Q·2^−λ_stat, so the oracle exposure a committee
//! may safely offer per epoch is finite. §7.2 turns that into an enforced
//! quantity rather than an assumption.
//!
//! Normative points implemented here, each traceable to the text:
//!
//! * **Per-key-epoch.** The budget is scoped to a key epoch and **§7.5
//!   proactive resharing resets it** — which is why the epoch chain and this
//!   module share an epoch number.
//! * **λ_stat relation.** "λ_stat ≥ λ_target + log₂(Q_max), λ_target = 40
//!   (equivalently: prefer λ_stat = 64)" ⇒ **Q_max ≤ 2^(λ_stat − λ_target)**.
//!   A configured Q_max above that ceiling is refused: it would silently
//!   weaken the flooding guarantee the budget exists to preserve.
//! * **What decrements.** "every operation that returns plaintext or
//!   plaintext-equivalent material — reveal, re-encryption to a user key,
//!   unshield — decrements the epoch budget; symbolic compute over handles
//!   (§8) decrements nothing." Compute never enters this API at all.
//! * **Two-level granularity.** Global per-key-epoch `Q_max`, plus
//!   **per-contract sub-budgets** (spec default `Q_max/64`) so one adversarial
//!   contract can neither consume the epoch's oracle capacity nor use
//!   exhaustion as a denial vector against unrelated applications.
//! * **Refusal at admission.** "rejected at admission (cheap, attributable,
//!   no partial state)" — [`EpochBudget::admit`] is called BEFORE any protocol
//!   work, and returns a refusal rather than performing a partial operation.
//! * **Public counters.** "Budget consumption counters are public per
//!   contract — oracle pressure is an observable, not a silent risk."
//!   [`EpochBudget::counters`] is that observable (feeds the G1
//!   dashboard line).
//!
//! `Q_max` itself is ⟦TBD, sized from §14.3 volume projections⟧ in the spec,
//! so it is configuration here — never a hardcoded constant.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Operations that return plaintext or plaintext-equivalent material and
/// therefore consume oracle budget (§7.2). Symbolic compute is deliberately
/// absent: it decrements nothing, so it has no representation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetedOp {
    /// §7.2 public reveal.
    Reveal,
    /// §7.3 re-encryption toward a user key.
    ReencryptToUser,
    /// §11 unshield (pool → public balance).
    Unshield,
}

impl BudgetedOp {
    pub fn label(&self) -> &'static str {
        match self {
            BudgetedOp::Reveal => "reveal",
            BudgetedOp::ReencryptToUser => "reencrypt-to-user",
            BudgetedOp::Unshield => "unshield",
        }
    }
}

/// §7.2 target statistical security. The spec fixes λ_target = 40.
pub const LAMBDA_TARGET: u32 = 40;
/// Spec's preferred flooding parameter ("equivalently: prefer λ_stat = 64").
///
/// ⚠️ PREFERRED, NOT PROVIDED. The deployed library's flooding parameter is
/// [`UPSTREAM_STATSEC`], and the decryption margin caps how far it can ever be
/// raised (see [`MAX_SAFE_LAMBDA_STAT`]). 64 exceeds that cap and is therefore
/// not implementable on the current construction; the constant is retained
/// because the spec text names it, and [`BudgetParams::validate`] refuses it.
pub const LAMBDA_STAT_PREFERRED: u32 = 64;

/// The flooding parameter of the PRODUCTION decrypt path — the number this
/// budget is physically backed by. The budget's λ_stat MUST equal it: a
/// budget computed from a larger value enforces a ceiling the flooding does
/// not provide; a smaller one wastes real capacity.
///
/// 50 as of the decrypt-path switch (2026-08-29): the production path is
/// the large-session TUniform route (`decrypt::DecryptSession::Large`,
/// the default), flooding at `STATSEC_TUNIFORM = 50` via the celar fork.
/// Mirror-tested against BOTH `decrypt::PRODUCTION_FLOODING_STATSEC` (so a
/// decrypt-path change breaks the suite, not the budget's honesty) and the
/// fork's exported constant (so an upstream change does the same).
pub const DEPLOYED_FLOODING_STATSEC: u32 = 50;

/// Hard ceiling on any future λ_stat, from the decryption margin — NOT a
/// tunable. Decryption rounds at Δ = 2^123 with message+carry in bits
/// 123..=126, so total noise must stay under Δ/2 = 2^122. The flooding mask
/// on the large-session path is bounded by 2^(70 + λ_stat + 1) and rides on
/// top of the real post-squash noise (≤ 2^70), giving
///   2^(71 + λ_stat) + 2^70 < 2^122  ⟺  λ_stat ≤ 50.
/// (Earlier analysis said 51; that neglected the additive 2^70 term, which
/// upstream's own tightness argument absorbs via PRSS-set slack that does
/// not exist on the flat path. 50 leaves 2× residual headroom; 51 leaves
/// none, which also matters for corruption resistance.)
///
/// Raising the library's STATSEC above this silently corrupts plaintexts:
/// there is no upstream assertion that the mask fits under Δ/2, and the
/// first hard error does not fire until 57.
pub const MAX_SAFE_LAMBDA_STAT: u32 = 50;
/// Spec default sub-budget divisor: "Q_max/64 per contract per epoch".
pub const SUB_BUDGET_DIVISOR: u64 = 64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BudgetParams {
    /// Global per-key-epoch budget. ⟦TBD in spec; sized from §14.3⟧ —
    /// configuration, never a constant.
    pub q_max: u64,
    /// Per-contract sub-budget. Defaults to `q_max / 64` per §7.2.
    pub per_contract_max: u64,
    /// Flooding statistical parameter actually in force.
    pub lambda_stat: u32,
    /// Target statistical security (§7.2 fixes 40).
    pub lambda_target: u32,
}

impl BudgetParams {
    /// Default parameters for a given Q_max: sub-budget = Q_max/64,
    /// λ_target = 40, and λ_stat = **what the production decrypt path
    /// provides** ([`DEPLOYED_FLOODING_STATSEC`]), not the spec's preferred
    /// 64 — defaulting to a value the flooding does not back was the defect
    /// the cross-check in [`Self::validate`] exists to refuse.
    pub fn with_q_max(q_max: u64) -> Self {
        Self {
            q_max,
            per_contract_max: (q_max / SUB_BUDGET_DIVISOR).max(1),
            lambda_stat: DEPLOYED_FLOODING_STATSEC,
            lambda_target: LAMBDA_TARGET,
        }
    }

    /// The largest Q_max the flooding parameter admits:
    /// λ_stat ≥ λ_target + log₂(Q_max) ⟺ Q_max ≤ 2^(λ_stat − λ_target).
    pub fn max_admissible_q_max(&self) -> u64 {
        match self.lambda_stat.checked_sub(self.lambda_target) {
            None | Some(0) => 0,
            Some(headroom) if headroom >= 64 => u64::MAX,
            Some(headroom) => 1u64 << headroom,
        }
    }

    /// Refuse configurations that would weaken the §7.2 guarantee.
    pub fn validate(&self) -> Result<()> {
        if self.q_max == 0 {
            bail!("Q_max must be positive");
        }
        // The λ cross-check: the configured flooding parameter must be the
        // one the deployed library provides. Refusal, not clamping — a
        // silently adjusted budget is a budget the operator believes wrongly.
        if self.lambda_stat != DEPLOYED_FLOODING_STATSEC {
            bail!(
                "λ_stat ({}) is not the flooding parameter the deployed \
                 production decrypt path provides ({}). A budget computed \
                 from a larger λ_stat enforces a ceiling the flooding does \
                 not back; one computed from a smaller value wastes real \
                 capacity. Either is a misconfiguration. Note the decryption \
                 margin caps λ_stat at {} permanently (Δ/2 = 2^122 vs a mask \
                 of 2^(71+λ_stat)); exceeding it corrupts plaintexts silently.",
                self.lambda_stat,
                DEPLOYED_FLOODING_STATSEC,
                MAX_SAFE_LAMBDA_STAT
            );
        }
        if self.lambda_stat <= self.lambda_target {
            bail!(
                "λ_stat ({}) must exceed λ_target ({}) — §7.2 requires \
                 λ_stat ≥ λ_target + log₂(Q_max), which leaves no budget at all \
                 when the two are equal",
                self.lambda_stat,
                self.lambda_target
            );
        }
        let ceiling = self.max_admissible_q_max();
        if self.q_max > ceiling {
            bail!(
                "Q_max {} exceeds the §7.2 flooding ceiling {} for λ_stat={} \
                 (λ_target={}): the requirement λ_stat ≥ λ_target + log₂(Q_max) \
                 would be violated, so the epoch's accumulated simulation \
                 distance ({}·2^−{}) would exceed the target. Either lower Q_max \
                 or raise λ_stat.",
                self.q_max,
                ceiling,
                self.lambda_stat,
                self.lambda_target,
                self.q_max,
                self.lambda_stat
            );
        }
        if self.per_contract_max == 0 || self.per_contract_max > self.q_max {
            bail!(
                "per-contract sub-budget {} must be in 1..=Q_max ({})",
                self.per_contract_max,
                self.q_max
            );
        }
        Ok(())
    }

    /// How many distinct contracts must each exhaust their sub-budget before
    /// the global budget can bind. §7.2: "the global budget is unreachable
    /// while any sub-budget binds" — with the default divisor this is 64.
    pub fn contracts_to_exhaust_global(&self) -> u64 {
        self.q_max.div_ceil(self.per_contract_max)
    }
}

/// Refusal reasons — public and attributable by design (§7.2: exhaustion is
/// "graceful and public").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetRefusal {
    ContractExhausted {
        contract: String,
        used: u64,
        limit: u64,
    },
    GlobalExhausted {
        used: u64,
        limit: u64,
    },
}

impl BudgetRefusal {
    pub fn describe(&self) -> String {
        match self {
            BudgetRefusal::ContractExhausted { contract, used, limit } => format!(
                "contract {contract} has consumed its epoch decryption sub-budget \
                 ({used}/{limit}); compute-only calls still proceed (§7.2)"
            ),
            BudgetRefusal::GlobalExhausted { used, limit } => format!(
                "the key epoch's global decryption budget is exhausted \
                 ({used}/{limit}); the KMS refuses further decryption-bearing \
                 service until §7.5 resharing opens a new epoch"
            ),
        }
    }
}

/// Public per-contract counters — the §7.2 observable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCounters {
    pub epoch: u64,
    pub q_max: u64,
    pub global_used: u64,
    pub per_contract_max: u64,
    pub per_contract_used: BTreeMap<String, u64>,
}

/// One key epoch's budget state.
#[derive(Debug, Clone)]
pub struct EpochBudget {
    epoch: u64,
    params: BudgetParams,
    global_used: u64,
    per_contract_used: BTreeMap<String, u64>,
}

impl EpochBudget {
    pub fn new(epoch: u64, params: BudgetParams) -> Result<Self> {
        params.validate()?;
        Ok(Self {
            epoch,
            params,
            global_used: 0,
            per_contract_used: BTreeMap::new(),
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn params(&self) -> &BudgetParams {
        &self.params
    }

    /// Admission check — call BEFORE any protocol work (§7.2: rejection is
    /// "cheap, attributable, no partial state"). Charges the operation on
    /// success; charges nothing on refusal.
    pub fn admit(&mut self, contract: &str, op: BudgetedOp) -> Result<(), BudgetRefusal> {
        let _ = op; // every budgeted op costs 1; kept for call-site clarity/logging
        let used = *self.per_contract_used.get(contract).unwrap_or(&0);
        if used >= self.params.per_contract_max {
            return Err(BudgetRefusal::ContractExhausted {
                contract: contract.to_string(),
                used,
                limit: self.params.per_contract_max,
            });
        }
        if self.global_used >= self.params.q_max {
            return Err(BudgetRefusal::GlobalExhausted {
                used: self.global_used,
                limit: self.params.q_max,
            });
        }
        self.per_contract_used
            .insert(contract.to_string(), used + 1);
        self.global_used += 1;
        Ok(())
    }

    /// §7.5 resharing opens a new epoch and RESETS the budget. Refuses to go
    /// backwards — a rolled-back epoch would silently restore spent oracle
    /// capacity.
    pub fn reset_for_epoch(&mut self, new_epoch: u64) -> Result<()> {
        if new_epoch <= self.epoch {
            bail!(
                "refusing to reset the decryption budget to epoch {new_epoch} \
                 from epoch {} — epochs advance, and replaying one would restore \
                 already-spent oracle capacity",
                self.epoch
            );
        }
        self.epoch = new_epoch;
        self.global_used = 0;
        self.per_contract_used.clear();
        Ok(())
    }

    /// The §7.2 public observable.
    pub fn counters(&self) -> PublicCounters {
        PublicCounters {
            epoch: self.epoch,
            q_max: self.params.q_max,
            global_used: self.global_used,
            per_contract_max: self.params.per_contract_max,
            per_contract_used: self.per_contract_used.clone(),
        }
    }

    /// Accumulated simulation distance exponent for the epoch so far:
    /// Q·2^−λ_stat, reported as log₂ ⇒ log₂(Q) − λ_stat.
    /// Included because §7.2's whole justification is this quantity.
    pub fn accumulated_distance_log2(&self) -> f64 {
        if self.global_used == 0 {
            f64::NEG_INFINITY
        } else {
            (self.global_used as f64).log2() - self.params.lambda_stat as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test fixture for admission-mechanics tests. Historically this
    /// lowered λ_target because no configuration validated at the real pair
    /// (40, 40); at the deployed (50, 40) the real headroom is 2^10 and the
    /// fixture is no longer load-bearing — kept only so mechanics tests
    /// have extra room and never couple to the ceiling. The mechanics under
    /// test (charging, refusal, reset, counters) do not depend on the pair.
    fn mech_params(q_max: u64) -> BudgetParams {
        let mut p = BudgetParams::with_q_max(q_max);
        p.lambda_target = 30;
        p
    }

    #[test]
    fn deployed_flooding_statsec_mirror_is_current() {
        // Two anchors, two failure modes caught: if the DECRYPT PATH changes
        // what it floods with, the first assert fails; if the FORK's
        // constant changes underneath us, the second does. Either way the
        // suite breaks instead of the budget silently un-backing.
        assert_eq!(
            DEPLOYED_FLOODING_STATSEC,
            crate::decrypt::PRODUCTION_FLOODING_STATSEC,
            "the production decrypt path's flooding parameter changed — \
             re-run the margin analysis before updating this mirror"
        );
        assert_eq!(
            DEPLOYED_FLOODING_STATSEC,
            threshold_execution::constants::STATSEC_TUNIFORM,
            "the fork's TUniform constant changed — re-derive the ceiling \
             before updating this mirror"
        );
    }

    #[test]
    fn lambda_relation_bounds_q_max() {
        // The relation itself: λ_stat ≥ λ_target + log₂(Q_max).
        let mut p = BudgetParams::with_q_max(1 << 24);
        p.lambda_stat = 64;
        assert_eq!(p.max_admissible_q_max(), 1 << 24);
        // At the future λ_stat = 50 the ceiling is 2^10 = 1024.
        p.lambda_stat = 50;
        assert_eq!(p.max_admissible_q_max(), 1 << 10);
    }

    #[test]
    fn preferred_lambda_is_refused_as_not_provided() {
        // The spec's preferred 64 is not what the library compiles, and the
        // margin analysis (E22a) showed it can never be. Must refuse.
        let mut p = BudgetParams::with_q_max(1 << 24);
        p.lambda_stat = LAMBDA_STAT_PREFERRED;
        let err = p.validate().unwrap_err().to_string();
        assert!(err.contains("not the flooding parameter"), "{err}");
    }

    #[test]
    fn the_shipped_budget_is_finally_real() {
        // The replacement assertion pre-written into this test's
        // predecessor (`current_truth_no_valid_budget_exists_yet`) the day
        // it was pinned, now activated: with the production decrypt path
        // flooding at 50 against λ_target = 40, the §7.2 ceiling is
        // 2^10 = 1024 — and the published number, the fork constant and
        // this enforcement finally agree.
        BudgetParams::with_q_max(1024).validate().unwrap();
        let mut over = BudgetParams::with_q_max(1025);
        over.per_contract_max = 1;
        let err = over.validate().unwrap_err().to_string();
        assert!(err.contains("flooding ceiling"), "{err}");
    }

    #[test]
    fn max_safe_lambda_stat_is_below_the_prf_error_floor() {
        // The first upstream *hard* error fires at STATSEC 57 (prf.rs bd1
        // bound). Everything in 51..=56 corrupts silently. Our cap must sit
        // strictly below the silent band, not just below the error.
        assert!(MAX_SAFE_LAMBDA_STAT < 51);
    }

    #[test]
    fn sub_budget_defaults_to_q_max_over_64() {
        let p = BudgetParams::with_q_max(6400);
        assert_eq!(p.per_contract_max, 100);
        // "the global budget is unreachable while any sub-budget binds":
        // it takes 64 saturated contracts to reach the global limit.
        assert_eq!(p.contracts_to_exhaust_global(), 64);
    }

    #[test]
    fn one_contract_cannot_consume_the_epoch() {
        // The denial-vector property: a single adversarial contract is capped
        // at its sub-budget, leaving the rest of the epoch for everyone else.
        let params = mech_params(640); // sub-budget 10
        let mut b = EpochBudget::new(1, params).unwrap();

        for _ in 0..10 {
            b.admit("0xadversary", BudgetedOp::Reveal).unwrap();
        }
        let refusal = b.admit("0xadversary", BudgetedOp::Reveal).unwrap_err();
        assert!(matches!(refusal, BudgetRefusal::ContractExhausted { .. }));
        assert!(refusal.describe().contains("compute-only calls still proceed"));

        // An unrelated contract is unaffected — that is the point.
        b.admit("0xhonest", BudgetedOp::ReencryptToUser).unwrap();
        assert_eq!(b.counters().global_used, 11);
    }

    #[test]
    fn refusal_charges_nothing() {
        // "no partial state": a refused admission must not consume budget.
        // Uses `mech_params` (counterfactual λ_target = 30) like every other
        // MECHANISM test: with the real deployed values λ_stat = λ_target = 40
        // the headroom is zero and NO budget is constructible at all — that
        // truth is asserted by `current_truth_no_valid_budget_exists_yet` and
        // `preferred_lambda_is_refused_as_not_provided`, and must not be
        // re-litigated here. `BudgetParams::with_q_max` therefore cannot be
        // used to test accounting behaviour.
        let mut params = mech_params(64);
        params.per_contract_max = 1;
        let mut b = EpochBudget::new(1, params).unwrap();

        b.admit("0xa", BudgetedOp::Reveal).unwrap();
        let before = b.counters().global_used;
        let _ = b.admit("0xa", BudgetedOp::Reveal).unwrap_err();
        assert_eq!(b.counters().global_used, before, "refusal must not charge");
    }

    #[test]
    fn global_budget_binds_across_many_contracts() {
        let mut params = mech_params(4);
        params.per_contract_max = 1; // 4 contracts × 1 = global
        let mut b = EpochBudget::new(1, params).unwrap();

        for i in 0..4 {
            b.admit(&format!("0x{i}"), BudgetedOp::Unshield).unwrap();
        }
        let refusal = b.admit("0x5", BudgetedOp::Unshield).unwrap_err();
        assert!(matches!(refusal, BudgetRefusal::GlobalExhausted { .. }));
        assert!(refusal.describe().contains("§7.5 resharing"));
    }

    #[test]
    fn resharing_resets_the_epoch_budget_but_never_rewinds() {
        // §7.5: "Proactive resharing resets the budget each epoch."
        let mut params = mech_params(64);
        params.per_contract_max = 1;
        let mut b = EpochBudget::new(1, params).unwrap();
        b.admit("0xa", BudgetedOp::Reveal).unwrap();
        assert!(b.admit("0xa", BudgetedOp::Reveal).is_err());

        b.reset_for_epoch(2).unwrap();
        assert_eq!(b.counters().global_used, 0);
        b.admit("0xa", BudgetedOp::Reveal).unwrap(); // fresh capacity

        // Replaying an epoch would restore spent oracle capacity.
        assert!(b.reset_for_epoch(2).is_err());
        assert!(b.reset_for_epoch(1).is_err());
    }

    #[test]
    fn counters_are_public_and_per_contract() {
        // 640 keeps q_max inside the fixture's real ceiling (2^10 = 1024).
        let mut b = EpochBudget::new(7, mech_params(640)).unwrap();
        b.admit("0xalpha", BudgetedOp::Reveal).unwrap();
        b.admit("0xalpha", BudgetedOp::ReencryptToUser).unwrap();
        b.admit("0xbeta", BudgetedOp::Unshield).unwrap();

        let c = b.counters();
        assert_eq!(c.epoch, 7);
        assert_eq!(c.global_used, 3);
        assert_eq!(c.per_contract_used["0xalpha"], 2);
        assert_eq!(c.per_contract_used["0xbeta"], 1);
        // Serialisable for the G1 dashboard line.
        assert!(serde_json::to_string(&c).unwrap().contains("0xalpha"));
    }

    #[test]
    fn accumulated_distance_tracks_the_flooding_argument() {
        // Q·2^−λ_stat at the deployed λ_stat: after 2^9 ops the exponent is
        // 9 − λ, computed from the constant rather than a literal so this
        // test cannot silently desynchronise from the mirror again.
        let mut b = EpochBudget::new(1, mech_params(1024)).unwrap();
        for i in 0..512 {
            b.admit(&format!("0x{}", i % 64), BudgetedOp::Reveal).unwrap();
        }
        let log2_dist = b.accumulated_distance_log2();
        let expected = 9.0 - DEPLOYED_FLOODING_STATSEC as f64;
        assert!((log2_dist - expected).abs() < 1e-9);
        assert!(log2_dist < -(LAMBDA_TARGET as f64));
    }
}
