//! E9: the AppHash trust boundary (B4 precondition; spec W20 makes the
//! light-client header a MUST).
//!
//! The ICS23 chain proves `AppHash ⊢ evm store ⊢ acl[h][grantee]` — but a
//! proof is only as trustworthy as its root. An AppHash taken from an RPC
//! response silently relocates the committee's trust from consensus to
//! whoever serves the endpoint: a KMS that verifies a beautiful ICS23 chain
//! against a root it was simply handed has proven nothing.
//!
//! This module makes the boundary explicit and mechanical:
//!
//! - [`AppHashSource`] names where a root came from — there are exactly two
//!   answers, and they are not interchangeable;
//! - [`TrustPolicy::admit`] is the gate: **unverified roots are REFUSED by
//!   default** (the same refusal posture as the G10 ACL property). Dev/test
//!   flows must opt in explicitly and the admitted root stays *tainted* so
//!   no downstream output can silently launder it into a trusted verdict;
//! - B4's authorization predicate MUST take an [`AdmittedAppHash`], never a
//!   raw `[u8; 32]` — the type is the enforcement.
//!
//! What this deliberately is NOT (per E9): a light client. The
//! `LightClientVerified` variant is the seam where one plugs in — the KMS
//! service (B2+) wires a real Tendermint light client (trusted checkpoint,
//! validator-set signature verification, bisection) and constructs the
//! variant from its verified headers. Until then nothing in this crate can
//! fabricate a trusted root: the only constructor callers reach in practice
//! is the unverified one, and it says so loudly.

use anyhow::{bail, Result};

/// Where an AppHash came from. The distinction IS the trust model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppHashSource {
    /// Verified by a Tendermint/CometBFT **light client** against a trusted
    /// checkpoint: header signatures checked against the known validator
    /// set, height monotonicity enforced. The only source the KMS trust
    /// path accepts (spec §7.4/G10, W20: MUST).
    LightClientVerified { app_hash: [u8; 32], height: u64 },
    /// Supplied by the caller (RPC response, file on disk, CLI flag) with
    /// **no verification**. Whoever produced it controls what the verifier
    /// believes about the chain. Dev and test flows only.
    UnverifiedCallerSupplied {
        app_hash: [u8; 32],
        height: Option<u64>,
    },
}

/// Gate policy. `Default` refuses unverified roots — production behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustPolicy {
    /// Explicit dev/test opt-in for unverified roots. Never set this on a
    /// path that serves real requests.
    pub allow_unverified: bool,
}

/// An AppHash that passed the gate. Carries its taint permanently:
/// `trusted == false` roots exist only behind the explicit dev opt-in, and
/// every consumer must surface the taint in its own output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedAppHash {
    pub app_hash: [u8; 32],
    pub height: Option<u64>,
    /// true ⇔ the root came from a light-client-verified header.
    pub trusted: bool,
}

impl TrustPolicy {
    /// The boundary. Refusal on an unverifiable root is the default and is
    /// deliberate: proving ACL state against an unproven root proves
    /// nothing, and a KMS must refuse rather than guess (G10 property).
    pub fn admit(&self, source: AppHashSource) -> Result<AdmittedAppHash> {
        match source {
            AppHashSource::LightClientVerified { app_hash, height } => Ok(AdmittedAppHash {
                app_hash,
                height: Some(height),
                trusted: true,
            }),
            AppHashSource::UnverifiedCallerSupplied { app_hash, height } => {
                if !self.allow_unverified {
                    bail!(
                        "REFUSED: the AppHash is caller-supplied and NOT light-client-verified. \
                         An unverified root proves nothing — whoever served it controls what \
                         this verifier believes (E9 trust boundary; spec W20 makes the \
                         light-client header a MUST). Dev/test flows may override with \
                         --allow-unverified-header, which taints the verdict."
                    );
                }
                Ok(AdmittedAppHash {
                    app_hash,
                    height,
                    trusted: false,
                })
            }
        }
    }
}

impl AdmittedAppHash {
    /// Suffix every human-readable verdict must carry so a tainted root can
    /// never be quoted as a trusted result.
    pub fn taint_label(&self) -> &'static str {
        if self.trusted {
            ""
        } else {
            " root=UNVERIFIED-DEV (not a trusted verdict)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 32] = [7u8; 32];

    #[test]
    fn unverified_is_refused_by_default() {
        // The E9 acceptance test: default policy + caller-supplied root ⇒ refusal.
        let err = TrustPolicy::default()
            .admit(AppHashSource::UnverifiedCallerSupplied {
                app_hash: HASH,
                height: Some(1002),
            })
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("REFUSED"), "refusal must be explicit: {msg}");
        assert!(
            msg.contains("light-client"),
            "refusal must state the boundary: {msg}"
        );
    }

    #[test]
    fn unverified_admitted_only_with_optin_and_stays_tainted() {
        let admitted = TrustPolicy {
            allow_unverified: true,
        }
        .admit(AppHashSource::UnverifiedCallerSupplied {
            app_hash: HASH,
            height: None,
        })
        .unwrap();
        assert!(!admitted.trusted);
        assert!(
            admitted.taint_label().contains("UNVERIFIED"),
            "taint must be visible in output"
        );
    }

    #[test]
    fn light_client_verified_is_trusted_under_default_policy() {
        let admitted = TrustPolicy::default()
            .admit(AppHashSource::LightClientVerified {
                app_hash: HASH,
                height: 1002,
            })
            .unwrap();
        assert!(admitted.trusted);
        assert_eq!(admitted.taint_label(), "");
        assert_eq!(admitted.height, Some(1002));
    }
}
