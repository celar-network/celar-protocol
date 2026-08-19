//! B4: the §7.4 authorization predicate — the committee's servability
//! decision, computed ONLY from proven state.
//!
//! This is the moment the KMS decides whether to produce a partial for a
//! request. Three properties are load-bearing:
//!
//! 1. **Inputs are proven, not asserted.** The predicate takes ACL state
//!    that arrived through the ICS23 read path under an [`AdmittedAppHash`]
//!    (E9) — a raw "trust me" word cannot even be passed in, and an
//!    untrusted (dev-tainted) root yields at most a tainted verdict.
//! 2. **Semantics mirror the chain exactly.** The rules are the shipped
//!    `checkServable` in `chain/celard/precompiles/fhe/fhe.go` (D1.5/D1.6,
//!    G9): re-encryption is servable for the handle's owner or a holder of
//!    `reencryptToSelf`; reveal ONLY for a holder of the explicit `reveal`
//!    grant (the owner gets nothing for free); unknown or absent state
//!    refuses. Divergence between chain and KMS here would let the two
//!    disagree about authorization — the exact seam §7.4 exists to close.
//! 3. **Refusal is the default.** Every failure mode — absent handle,
//!    absent grant, wrong permission, untrusted root — refuses with a
//!    stated reason. The KMS never guesses (G10 refusal property).
//!
//! The fraud side of §7.4 (`fraud.rs`) is this predicate run in the other
//! direction: evidence that a seat served a request this predicate refuses.

use serde::{Deserialize, Serialize};

use crate::acl::{HandleMeta, PERM_BIT_REENCRYPT_TO_SELF, PERM_BIT_REVEAL};
use crate::header_trust::AdmittedAppHash;

/// What is being asked of the committee (§7.3 / §7.2 exits to plaintext).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestKind {
    /// Re-encrypt toward the requester's key (private read).
    Reencrypt,
    /// Public reveal (permanent disclosure).
    Reveal,
}

/// A decryption-bearing request, as the KMS sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub kind: RequestKind,
    /// The ciphertext handle (32 bytes, hex).
    pub handle: String,
    /// The requesting address (20 bytes, hex, lowercase).
    pub requester: String,
}

/// The proven ACL state for one (handle, requester) pair at one height —
/// the OUTPUT of the ICS23 read path, never hand-assembled from RPC values.
#[derive(Debug, Clone)]
pub struct ProvenAclState {
    /// The root everything below was proven against (E9 gate applied).
    pub root: AdmittedAppHash,
    /// handleMeta[h], decoded — None if proven ABSENT.
    pub meta: Option<HandleMeta>,
    /// acl[h][requester] permission word — None if proven ABSENT.
    pub acl_word: Option<[u8; 32]>,
}

/// The predicate's answer. `Servable` carries the taint of its root: a
/// verdict from a dev-tainted root is marked and MUST NOT be served against
/// real requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Servable {
        /// false ⇔ the root was dev-tainted (§ E9) — not a production verdict.
        trusted_root: bool,
    },
    Refused {
        reason: RefusalReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// handleMeta[h] proven absent — the handle was never registered.
    UnknownHandle,
    /// Meta present but the exists flag is unset.
    HandleNotLive,
    /// Reencrypt: requester is neither owner nor `reencryptToSelf` grantee.
    ReencryptNotAuthorized,
    /// Reveal: no explicit `reveal` grant for this handle.
    RevealNotGranted,
}

impl RefusalReason {
    pub fn describe(&self) -> &'static str {
        match self {
            RefusalReason::UnknownHandle => {
                "handle was never registered — nothing to authorize against"
            }
            RefusalReason::HandleNotLive => "handle metadata present but not live",
            RefusalReason::ReencryptNotAuthorized => {
                "requester is neither the handle owner nor a reencrypt-to-self grantee"
            }
            RefusalReason::RevealNotGranted => {
                "no explicit reveal grant for this handle (owner gets no free reveal)"
            }
        }
    }
}

/// The §7.4 servability predicate. Pure: same proven state ⇒ same verdict,
/// which is what makes refused-but-served requests *provable* fraud.
pub fn evaluate(request: &Request, state: &ProvenAclState) -> Verdict {
    let meta = match &state.meta {
        None => {
            return Verdict::Refused {
                reason: RefusalReason::UnknownHandle,
            }
        }
        Some(m) => m,
    };
    if !meta.exists {
        return Verdict::Refused {
            reason: RefusalReason::HandleNotLive,
        };
    }

    let perm_bits = state.acl_word.map(|w| w[31]).unwrap_or(0);
    let requester = request.requester.to_ascii_lowercase();
    let owner = meta.owner.to_ascii_lowercase();

    let authorized = match request.kind {
        // Mirrors fhe.go checkServable: owner OR reencryptToSelf grantee.
        RequestKind::Reencrypt => {
            requester == owner || perm_bits & PERM_BIT_REENCRYPT_TO_SELF != 0
        }
        // Mirrors fhe.go checkServable: explicit grant only — even the owner.
        RequestKind::Reveal => perm_bits & PERM_BIT_REVEAL != 0,
    };

    if authorized {
        Verdict::Servable {
            trusted_root: state.root.trusted,
        }
    } else {
        Verdict::Refused {
            reason: match request.kind {
                RequestKind::Reencrypt => RefusalReason::ReencryptNotAuthorized,
                RequestKind::Reveal => RefusalReason::RevealNotGranted,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::PERM_BIT_COMPUTE;

    const OWNER: &str = "0xbcaaca89b8d26de23e9039507c1645fcd185c1ee";
    const STRANGER: &str = "0xc000000000000000000000000000000000000003";

    fn trusted_root() -> AdmittedAppHash {
        AdmittedAppHash {
            app_hash: [7u8; 32],
            height: Some(1002),
            trusted: true,
        }
    }

    fn meta(owner: &str, exists: bool) -> HandleMeta {
        HandleMeta {
            owner: owner.to_string(),
            ktype: 6,
            exists,
        }
    }

    fn word(bits: u8) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[31] = bits;
        w
    }

    fn req(kind: RequestKind, requester: &str) -> Request {
        Request {
            kind,
            handle: "0x13dd".into(),
            requester: requester.into(),
        }
    }

    fn state(
        meta_v: Option<HandleMeta>,
        acl: Option<[u8; 32]>,
        trusted: bool,
    ) -> ProvenAclState {
        let mut root = trusted_root();
        root.trusted = trusted;
        ProvenAclState {
            root,
            meta: meta_v,
            acl_word: acl,
        }
    }

    // ---- mirrors of the chain-side unit tests (storage_acl_test.go) ------

    #[test]
    fn owner_may_reencrypt_without_any_grant() {
        let v = evaluate(
            &req(RequestKind::Reencrypt, OWNER),
            &state(Some(meta(OWNER, true)), None, true),
        );
        assert_eq!(v, Verdict::Servable { trusted_root: true });
    }

    #[test]
    fn stranger_reencrypt_requires_the_grant() {
        let s_no = state(Some(meta(OWNER, true)), None, true);
        assert!(matches!(
            evaluate(&req(RequestKind::Reencrypt, STRANGER), &s_no),
            Verdict::Refused {
                reason: RefusalReason::ReencryptNotAuthorized
            }
        ));

        let s_yes = state(
            Some(meta(OWNER, true)),
            Some(word(PERM_BIT_REENCRYPT_TO_SELF)),
            true,
        );
        assert_eq!(
            evaluate(&req(RequestKind::Reencrypt, STRANGER), &s_yes),
            Verdict::Servable { trusted_root: true }
        );
    }

    #[test]
    fn reveal_needs_explicit_grant_even_for_owner() {
        let s_owner_no_grant = state(Some(meta(OWNER, true)), None, true);
        assert!(matches!(
            evaluate(&req(RequestKind::Reveal, OWNER), &s_owner_no_grant),
            Verdict::Refused {
                reason: RefusalReason::RevealNotGranted
            }
        ));

        let s_granted = state(Some(meta(OWNER, true)), Some(word(PERM_BIT_REVEAL)), true);
        assert_eq!(
            evaluate(&req(RequestKind::Reveal, STRANGER), &s_granted),
            Verdict::Servable { trusted_root: true }
        );
    }

    #[test]
    fn compute_grant_never_escalates_to_decryption() {
        // The three-permission separation: compute must not decrypt.
        let s = state(Some(meta(OWNER, true)), Some(word(PERM_BIT_COMPUTE)), true);
        assert!(matches!(
            evaluate(&req(RequestKind::Reencrypt, STRANGER), &s),
            Verdict::Refused { .. }
        ));
        assert!(matches!(
            evaluate(&req(RequestKind::Reveal, STRANGER), &s),
            Verdict::Refused { .. }
        ));
    }

    #[test]
    fn absent_or_dead_handles_refuse() {
        assert!(matches!(
            evaluate(&req(RequestKind::Reencrypt, OWNER), &state(None, None, true)),
            Verdict::Refused {
                reason: RefusalReason::UnknownHandle
            }
        ));
        assert!(matches!(
            evaluate(
                &req(RequestKind::Reveal, OWNER),
                &state(Some(meta(OWNER, false)), Some(word(0xFF)), true)
            ),
            Verdict::Refused {
                reason: RefusalReason::HandleNotLive
            }
        ));
    }

    #[test]
    fn tainted_root_taints_the_verdict() {
        // E9 carried through: a dev root can authorize, but never untainted.
        let v = evaluate(
            &req(RequestKind::Reencrypt, OWNER),
            &state(Some(meta(OWNER, true)), None, false),
        );
        assert_eq!(
            v,
            Verdict::Servable {
                trusted_root: false
            }
        );
    }
}
