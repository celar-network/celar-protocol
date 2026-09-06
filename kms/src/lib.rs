//! Celar threshold KMS.
//!
//! Skeleton: a local n-party DKG run (whitepaper §7.1) over the
//! `zama-ai/kms` `threshold-execution` protocol crate, producing a published,
//! re-verifiable transcript artifact. Permissioned genesis mode first (§7.7):
//! party count comes from config, reconstruction quorum t = ⌊3c/4⌋+1.
//!
//! Skeleton honesty (labelled, per house rule):
//! - preprocessing is `DummyPreprocessing` (the real offline phase is the
//!   expensive part; it swaps in behind `dkg::run_local_dkg` without touching
//!   the transcript format);
//! - networking is the upstream local test runtime (real deployment is
//!   gRPC/mTLS per spike S2, one process per committee member);
//! - the transcript commits to shares (hashes), it never contains them.

pub mod acl;
#[cfg(test)]
mod degree_coupling_tests;
pub mod authz;
pub mod budget;
pub mod committee;
pub mod config;
pub mod decrypt;
pub mod dkg;
pub mod fraud;
pub mod header_trust;
pub mod ics23_verify;
pub mod mask_supply;
pub mod mpt;
pub mod node;
pub mod noise_probe;
pub mod reencrypt;
pub mod reshare;
pub mod transcript;

/// Sharing-domain extension degree used throughout.
///
/// **This is a committee-size constraint, not just a performance knob.** Party
/// evaluation points come from an exceptional sequence of exactly
/// `2^EXTENSION_DEGREE` elements with index 0 reserved for the secret, so the
/// degree sets a hard ceiling of `2^EXTENSION_DEGREE - 1` parties. See
/// `config::MAX_PARTIES`, which is derived from this and asserted at compile time
/// against the §7.7 genesis range.
///
/// **Raised 4 → 7 on 2026-08-20.** At 4 the ceiling was 15 parties while
/// `committee.rs` refused any committee under 30 — no committee size was
/// constructible, and it went unnoticed because every run to date is c=4 and the
/// "genesis-scale" tests exercised roster rules rather than a sharing. Found while
/// from the λ-blowup check and the committee-size finding.
///
/// Why 7 rather than 6: degree 6 gives 63 parties, which covers the genesis range
/// 30–50 but **not** §7.7's permissionless c=100, so it would buy a second
/// migration later. Degree 7 gives 127 and covers every committee size the
/// whitepaper publishes. The cost is real and must be measured — a residue
/// polynomial carries `EXTENSION_DEGREE` coefficients, so ring arithmetic, share
/// size, PRSS and DKG all widen by ~1.75× against the recorded 4-degree baseline
/// (secure DKG 98.9 s at c=4). If measurement rules 7 out, 6 remains available and
/// the compile-time assertion still holds for the genesis range alone.
pub const EXTENSION_DEGREE: usize = 7;

/// The upstream pin, recorded into every transcript. Pin history:
/// zama v0.13.22 (tfhe 1.6.1) → zama main@c6b0fdd3 (tfhe 1.7.0, aligning
/// with the compute backend) → celar-network/kms@8015482e (one commit on
/// c6b0fdd3: per-path flooding parameter, STATSEC_TUNIFORM = 50, ceiling
/// assertions — the vendor accepts no external PRs, so the fork is the
/// standing carrier; proposed upstream as zama-ai/kms#807/#808).
/// A transcript's pin now names the FORK — deliberately, since the flooding
/// parameter it implies differs from the vendor tree's.
pub const UPSTREAM_REPO: &str = "https://github.com/celar-network/kms";
pub const UPSTREAM_TAG: &str = "celar/statsec-tuniform-50@8015482e5ef14a2f57b1f792e584a7fa0533d728";
