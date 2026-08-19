//! B4: §7.4 fraud-proof verification — an unauthorized partial is
//! self-contained evidence.
//!
//! The §7.4 claim: if a committee seat serves a decryption-bearing request
//! that the authorization predicate refuses, the *artifact of serving it*
//! convicts the seat — anyone can verify the fraud from the evidence alone,
//! with no trusted party. This module defines that evidence and its verifier.
//!
//! [`FraudEvidence`] is self-contained by construction:
//! - the [`RequestRecord`] the seat committed to (canonical bytes, domain-
//!   separated — what the seat signs before serving);
//! - the seat's signature over those bytes;
//! - the raw ICS23 proof bundles for `handleMeta[h]` and `acl[h][requester]`
//!   at the record's height — NOT an eth_getProof JSON blob but our own
//!   canonical envelope, verified here from bytes up.
//!
//! Verification chain: admit the root (E9 gate — **fraud claims require a
//! light-client-verified root**; a "fraud proof" against a dev-tainted root
//! proves nothing and is rejected as evidence) → re-prove both slots →
//! run the §7.4 predicate → it must REFUSE → check the seat's signature.
//! All four hold ⇔ fraud. Anything else is NotFraud with the reason stated —
//! a fraud verifier that can convict on weak evidence is itself an attack
//! surface (framing).
//!
//! Deliberately deferred (stated, not hidden):
//! - **Seat signature scheme.** Real serving commitments will be bound to
//!   the DKG/partial-decryption material (B2; the W8 accountable-decryption
//!   construction strengthens this further — request-bound partials via
//!   ek_i). Until B2 lands, [`SeatSignatureVerifier`] is a trait; production
//!   wiring chooses the scheme when the keys exist.
//! - **Slash wiring** is chain-side (severe slash on conviction) — routed
//!   through the eng work orders, since it touches `celard` and possibly a
//!   new surface beside the frozen ABI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::acl::{acl_slot, decode_meta, meta_slot, FHE_PRECOMPILE_ADDRESS};
use crate::authz::{evaluate, ProvenAclState, Request, RequestKind, Verdict};
use crate::header_trust::{AppHashSource, TrustPolicy};
use crate::ics23_verify::{verify_slot, SlotOutcome};

/// Domain separator for seat serving commitments. Versioned: bump on any
/// change to the signing-bytes layout.
pub const SERVE_DOMAIN: &[u8] = b"celar.kms.serve.v0";

/// What a seat commits to when it decides to serve a request. The height
/// pins WHICH chain state the seat claims authorized it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    pub kind: RequestKind,
    /// Handle, 32 bytes hex (0x-prefixed).
    pub handle: String,
    /// Requester address, 20 bytes hex (0x-prefixed).
    pub requester: String,
    /// CometBFT height of the header whose AppHash the ACL was proven under.
    pub header_height: u64,
    /// One-based committee role of the serving seat.
    pub seat_role: usize,
}

impl RequestRecord {
    /// Canonical bytes the seat signs. Fixed layout, domain-separated:
    /// tag ‖ kind ‖ handle(32) ‖ requester(20) ‖ height(8 BE) ‖ role(8 BE).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let handle = hex::decode(self.handle.trim_start_matches("0x"))
            .context("record.handle is not hex")?;
        let requester = hex::decode(self.requester.trim_start_matches("0x"))
            .context("record.requester is not hex")?;
        if handle.len() != 32 || requester.len() != 20 {
            anyhow::bail!("record field lengths wrong (handle 32B, requester 20B)");
        }
        let mut out = Vec::with_capacity(SERVE_DOMAIN.len() + 1 + 32 + 20 + 16);
        out.extend_from_slice(SERVE_DOMAIN);
        out.push(match self.kind {
            RequestKind::Reencrypt => 0x01,
            RequestKind::Reveal => 0x02,
        });
        out.extend_from_slice(&handle);
        out.extend_from_slice(&requester);
        out.extend_from_slice(&self.header_height.to_be_bytes());
        out.extend_from_slice(&(self.seat_role as u64).to_be_bytes());
        Ok(out)
    }
}

/// Verifies a seat's signature over its serving commitment. The concrete
/// scheme arrives with B2's key material; tests use a double.
pub trait SeatSignatureVerifier {
    fn verify(&self, seat_role: usize, message: &[u8], signature: &[u8]) -> bool;
}

/// One slot's canonical proof bundle inside evidence: the two ICS23 layers
/// exactly as the read path consumes them ([iavl, multistore]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotProofBundle {
    pub layers: Vec<Vec<u8>>,
}

/// Self-contained §7.4 fraud evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudEvidence {
    pub record: RequestRecord,
    /// Seat signature over `record.signing_bytes()`.
    pub seat_signature: Vec<u8>,
    /// AppHash of the header at `record.header_height` (the root the slot
    /// proofs verify against). Its VERIFICATION status is supplied by the
    /// caller as an [`AppHashSource`] — evidence bytes cannot self-certify
    /// trust (that is the whole E9 point).
    pub app_hash: [u8; 32],
    pub meta_proof: SlotProofBundle,
    pub acl_proof: SlotProofBundle,
}

/// Outcome of fraud verification.
#[derive(Debug, PartialEq, Eq)]
pub enum FraudVerdict {
    /// All four checks held: root trusted, state proven, predicate REFUSED,
    /// signature valid. The seat served what it must not serve.
    Fraudulent {
        seat_role: usize,
        refusal: &'static str,
    },
    /// Evidence does not establish fraud; the reason is stated.
    NotFraud { why: String },
}

/// Verify §7.4 fraud evidence from bytes up.
///
/// `root_source` states how the caller obtained/verified the header for
/// `record.header_height`; only a light-client-verified root can support a
/// conviction (default `TrustPolicy` — no override parameter on purpose:
/// there is no legitimate dev-mode conviction).
pub fn verify_fraud(
    evidence: &FraudEvidence,
    root_source: AppHashSource,
    sig_verifier: &dyn SeatSignatureVerifier,
) -> Result<FraudVerdict> {
    // 1) E9 gate, strict: convictions demand a trusted root.
    let admitted = match TrustPolicy::default().admit(root_source) {
        Ok(a) => a,
        Err(e) => {
            return Ok(FraudVerdict::NotFraud {
                why: format!("root not admissible for conviction: {e}"),
            })
        }
    };
    if admitted.app_hash != evidence.app_hash {
        return Ok(FraudVerdict::NotFraud {
            why: "evidence app_hash does not match the verified header's AppHash".into(),
        });
    }
    if admitted.height != Some(evidence.record.header_height) {
        return Ok(FraudVerdict::NotFraud {
            why: format!(
                "verified header height {:?} does not match the record's {}",
                admitted.height, evidence.record.header_height
            ),
        });
    }

    // 2) Re-prove both slots from the evidence's own bytes.
    let handle: [u8; 32] = decode_fixed(&evidence.record.handle).context("record.handle")?;
    let requester: [u8; 20] =
        decode_fixed(&evidence.record.requester).context("record.requester")?;

    let meta = match verify_slot(
        &evidence.app_hash,
        &FHE_PRECOMPILE_ADDRESS,
        &meta_slot(&handle),
        &evidence.meta_proof.layers,
    )
    .context("meta slot proof")?
    {
        SlotOutcome::Present(w) => Some(decode_meta(&w)),
        SlotOutcome::Absent => None,
    };
    let acl_word = match verify_slot(
        &evidence.app_hash,
        &FHE_PRECOMPILE_ADDRESS,
        &acl_slot(&handle, &requester),
        &evidence.acl_proof.layers,
    )
    .context("acl slot proof")?
    {
        SlotOutcome::Present(w) => Some(w),
        SlotOutcome::Absent => None,
    };

    // 3) The predicate must REFUSE the request at that proven state.
    let request = Request {
        kind: evidence.record.kind,
        handle: evidence.record.handle.clone(),
        requester: evidence.record.requester.clone(),
    };
    let state = ProvenAclState {
        root: admitted,
        meta,
        acl_word,
    };
    let refusal = match evaluate(&request, &state) {
        Verdict::Refused { reason } => reason.describe(),
        Verdict::Servable { .. } => {
            return Ok(FraudVerdict::NotFraud {
                why: "the request was AUTHORIZED at the proven state — serving it \
                      was legitimate"
                    .into(),
            })
        }
    };

    // 4) The seat must actually have committed to serving it.
    let msg = evidence.record.signing_bytes()?;
    if !sig_verifier.verify(evidence.record.seat_role, &msg, &evidence.seat_signature) {
        return Ok(FraudVerdict::NotFraud {
            why: "seat signature does not verify — no proof this seat served the \
                  request (framing attempt or corrupt evidence)"
                .into(),
        });
    }

    Ok(FraudVerdict::Fraudulent {
        seat_role: evidence.record.seat_role,
        refusal,
    })
}

fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != N {
        anyhow::bail!("expected {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test double: signature = signing bytes XOR a per-role byte.
    struct TestSigner;
    impl TestSigner {
        fn sign(role: usize, msg: &[u8]) -> Vec<u8> {
            msg.iter().map(|b| b ^ (role as u8)).collect()
        }
    }
    impl SeatSignatureVerifier for TestSigner {
        fn verify(&self, role: usize, msg: &[u8], sig: &[u8]) -> bool {
            Self::sign(role, msg) == sig
        }
    }

    const HANDLE: &str = "0x13dd2bcf291df94a006996bdfcd9bb8830bbee1218b59d4aa4ec3de2d4502efd";
    const REQUESTER: &str = "0xc000000000000000000000000000000000000003";

    fn record(kind: RequestKind) -> RequestRecord {
        RequestRecord {
            kind,
            handle: HANDLE.into(),
            requester: REQUESTER.into(),
            header_height: 1002,
            seat_role: 3,
        }
    }

    fn evidence(kind: RequestKind, sign_role: usize) -> FraudEvidence {
        let rec = record(kind);
        let sig = TestSigner::sign(sign_role, &rec.signing_bytes().unwrap());
        FraudEvidence {
            record: rec,
            seat_signature: sig,
            app_hash: [9u8; 32],
            // Structurally invalid proofs — tests below never reach step 2
            // for these, or expect the proof error.
            meta_proof: SlotProofBundle { layers: vec![] },
            acl_proof: SlotProofBundle { layers: vec![] },
        }
    }

    fn trusted_source() -> AppHashSource {
        AppHashSource::LightClientVerified {
            app_hash: [9u8; 32],
            height: 1002,
        }
    }

    #[test]
    fn conviction_requires_a_trusted_root() {
        // A dev/unverified root can NEVER support a conviction.
        let v = verify_fraud(
            &evidence(RequestKind::Reveal, 3),
            AppHashSource::UnverifiedCallerSupplied {
                app_hash: [9u8; 32],
                height: Some(1002),
            },
            &TestSigner,
        )
        .unwrap();
        assert!(
            matches!(v, FraudVerdict::NotFraud { ref why } if why.contains("not admissible")),
            "{v:?}"
        );
    }

    #[test]
    fn root_and_height_must_match_the_record() {
        let v = verify_fraud(
            &evidence(RequestKind::Reveal, 3),
            AppHashSource::LightClientVerified {
                app_hash: [1u8; 32], // wrong root
                height: 1002,
            },
            &TestSigner,
        )
        .unwrap();
        assert!(matches!(v, FraudVerdict::NotFraud { ref why } if why.contains("AppHash")));

        let v = verify_fraud(
            &evidence(RequestKind::Reveal, 3),
            AppHashSource::LightClientVerified {
                app_hash: [9u8; 32],
                height: 999, // wrong height
            },
            &TestSigner,
        )
        .unwrap();
        assert!(matches!(v, FraudVerdict::NotFraud { ref why } if why.contains("height")));
    }

    #[test]
    fn malformed_slot_proofs_are_an_error_not_a_conviction() {
        // With root/height matching, step 2 runs — and empty proof layers
        // must ERROR (invalid evidence), never convict.
        let e = verify_fraud(&evidence(RequestKind::Reveal, 3), trusted_source(), &TestSigner);
        assert!(e.is_err(), "malformed proofs must be an error: {e:?}");
    }

    #[test]
    fn signing_bytes_are_domain_separated_and_field_sensitive() {
        let a = record(RequestKind::Reveal).signing_bytes().unwrap();
        assert!(a.starts_with(SERVE_DOMAIN));

        let b = record(RequestKind::Reencrypt).signing_bytes().unwrap();
        assert_ne!(a, b, "kind must alter the signed bytes");

        let mut r = record(RequestKind::Reveal);
        r.header_height = 1003;
        assert_ne!(a, r.signing_bytes().unwrap(), "height must alter the signed bytes");

        let mut r = record(RequestKind::Reveal);
        r.seat_role = 4;
        assert_ne!(a, r.signing_bytes().unwrap(), "seat must alter the signed bytes");
    }

    #[test]
    fn wrong_seat_signature_is_framing_not_fraud() {
        // Signature made by role 2 presented as role 3's commitment: the
        // signature check must fail — but we can only reach step 4 with
        // valid proofs, so this exercises the verifier double directly.
        let rec = record(RequestKind::Reveal);
        let msg = rec.signing_bytes().unwrap();
        let sig_by_2 = TestSigner::sign(2, &msg);
        assert!(!TestSigner.verify(3, &msg, &sig_by_2));
        assert!(TestSigner.verify(2, &msg, &sig_by_2));
    }
}
