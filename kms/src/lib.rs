//! Celar threshold KMS — Track B.
//!
//! B1 skeleton: a local n-party DKG run (whitepaper §7.1) over the
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
pub mod authz;
pub mod committee;
pub mod config;
pub mod dkg;
pub mod header_trust;
pub mod ics23_verify;
pub mod mpt;
pub mod node;
pub mod reshare;
pub mod transcript;

/// Sharing-domain extension degree used throughout (upstream default feature
/// `extension_degree_4`).
pub const EXTENSION_DEGREE: usize = 4;

/// The upstream pin, recorded into every transcript.
pub const UPSTREAM_REPO: &str = "https://github.com/zama-ai/kms";
pub const UPSTREAM_TAG: &str = "v0.13.22";
