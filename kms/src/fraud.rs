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
///
/// v0 → v1 (2026-08-20): `epoch` added to the record and to the signed
/// layout. The bump was free — no seat signatures existed yet — and the
/// reason it is in the SIGNED bytes rather than alongside them: a seat must
/// commit to WHICH key epoch it served under, or an accuser could re-point
/// otherwise-valid evidence at a different epoch's archived commitments.
pub const SERVE_DOMAIN: &[u8] = b"celar.kms.serve.v1";

/// What a seat commits to when it decides to serve a request. The height
/// pins WHICH chain state the seat claims authorized it; the epoch pins
/// WHICH key epoch (and therefore which archived seat commitments C_i^(e))
/// the service happened under — without it, evidence cannot name its own
/// archive entry, which breaks self-containment the moment a reshare lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    pub kind: RequestKind,
    /// Handle, 32 bytes hex (0x-prefixed).
    pub handle: String,
    /// Requester address, 20 bytes hex (0x-prefixed).
    pub requester: String,
    /// Key epoch the seat served under (genesis DKG = 0, §7.5 chain).
    pub epoch: u64,
    /// CometBFT height of the header whose AppHash the ACL was proven under.
    pub header_height: u64,
    /// One-based committee role of the serving seat.
    pub seat_role: usize,
}

impl RequestRecord {
    /// Canonical bytes the seat signs. Fixed layout, domain-separated:
    /// tag ‖ kind ‖ handle(32) ‖ requester(20) ‖ epoch(8 BE) ‖ height(8 BE) ‖ role(8 BE).
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let handle = hex::decode(self.handle.trim_start_matches("0x"))
            .context("record.handle is not hex")?;
        let requester = hex::decode(self.requester.trim_start_matches("0x"))
            .context("record.requester is not hex")?;
        if handle.len() != 32 || requester.len() != 20 {
            anyhow::bail!("record field lengths wrong (handle 32B, requester 20B)");
        }
        let mut out = Vec::with_capacity(SERVE_DOMAIN.len() + 1 + 32 + 20 + 24);
        out.extend_from_slice(SERVE_DOMAIN);
        out.push(match self.kind {
            RequestKind::Reencrypt => 0x01,
            RequestKind::Reveal => 0x02,
        });
        out.extend_from_slice(&handle);
        out.extend_from_slice(&requester);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.header_height.to_be_bytes());
        out.extend_from_slice(&(self.seat_role as u64).to_be_bytes());
        Ok(out)
    }
}

/// One seat's archived commitment for one epoch, as the chain retains it
/// (§7.5: per-epoch C_i^(e) in chain state; the epochcommit store).
///
/// FIELD ORDER IS CANONICAL and pinned to proto field numbers 1..=4 in
/// declaration order (agreed with the chain side, 2026-08-29). If an entry
/// is ever hashed, it is hashed in its proto encoding under these numbers —
/// no other canonical form exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedSeatCommitment {
    /// 1 — The seat's share commitment for that epoch (sha256 hex today,
    /// matching `ReshareTranscript`; becomes the C_i the π-relation binds).
    pub commitment_sha256: String,
    /// 2 — Roster digest for that epoch. Roles are per-committee indices, so
    /// across a membership change "role 3" alone names nobody — this binds
    /// the role to an identity set.
    pub roster_sha256: String,
    /// 3 — Height at which this epoch was keyed (established on chain).
    /// A record claiming service under this epoch at an earlier header
    /// height is malformed: nothing can be served under a key that did not
    /// yet exist.
    pub keyed_height: u64,
    /// 4 — pk_G digest, invariant across epochs; binds the entry to the key
    /// it belongs to, so evidence carries a key-identity anchor.
    pub pk_g_sha256: String,
}

/// Cross-checks a request record against the archived entry its epoch
/// resolves to. Split out of `verify_fraud` so the binding rules are
/// directly testable. Malformation ERRORS (framing resistance) — it neither
/// convicts nor acquits.
fn check_entry_binding(record: &RequestRecord, entry: &ArchivedSeatCommitment) -> Result<()> {
    if record.header_height < entry.keyed_height {
        anyhow::bail!(
            "malformed evidence: record claims service at header height {} but \
             epoch {} was not keyed until height {} — nothing can be served \
             under a key that did not yet exist",
            record.header_height,
            record.epoch,
            entry.keyed_height
        );
    }
    Ok(())
}

/// Read seam over the chain's per-epoch commitment archive (engineer #1's
/// D7 store; the eventual impl proves reads via ICS23 like every other
/// chain fact the KMS consumes). The shape is the E25 answer: point read
/// on (epoch, seat_role), plus two NEVER-pruned bounds that make absence
/// decidable rather than inferred from a missing key.
pub trait EpochCommitmentArchive {
    /// (oldest_retained_epoch, latest_epoch). Both survive pruning.
    fn bounds(&self) -> (u64, u64);
    /// The commitment for one seat in one epoch, if retained.
    ///
    /// `seat_role` is the WIRE TYPE agreed with the chain side (2026-08-29):
    /// `u32`, **1-based, 0 invalid** — callers must reject 0 before lookup;
    /// an off-by-one here convicts the wrong seat.
    fn commitment(&self, epoch: u64, seat_role: u32) -> Option<ArchivedSeatCommitment>;
}

/// Outcome of resolving an epoch against the archive. Three absence cases,
/// three different meanings — collapsing them lets expired evidence read as
/// forged (defaming an accuser) or forged evidence read as expired (excusing
/// a fabrication).
enum ArchiveResolution {
    Found(ArchivedSeatCommitment),
    /// epoch < oldest_retained: pruned past the §7.4 horizon. A verdict
    /// about the evidence (time-barred), NOT corruption of it.
    TimeBarred { oldest_retained: u64 },
    /// epoch > latest: names an epoch the chain never established.
    /// Malformed — errors, never convicts (framing resistance).
    NeverExisted { latest: u64 },
    /// In range but absent: should be impossible. An anomaly is an error,
    /// never a conviction.
    AnomalousGap,
}

fn resolve_epoch(
    archive: &dyn EpochCommitmentArchive,
    epoch: u64,
    seat_role: u32,
) -> ArchiveResolution {
    let (oldest, latest) = archive.bounds();
    if epoch < oldest {
        return ArchiveResolution::TimeBarred {
            oldest_retained: oldest,
        };
    }
    if epoch > latest {
        return ArchiveResolution::NeverExisted { latest };
    }
    match archive.commitment(epoch, seat_role) {
        Some(c) => ArchiveResolution::Found(c),
        None => ArchiveResolution::AnomalousGap,
    }
}

/// Verifies a seat's signature over its serving commitment, against that
/// seat's archived commitment FOR THE EPOCH THE RECORD NAMES — not the
/// current one; that is the whole point of the archive. The concrete scheme
/// arrives with B2's key material (and per the A-Q15 constraints it becomes
/// a ZK relation, not a signature — this trait is the seam, and its shape
/// already carries the commitment so the seam does not move again).
pub trait SeatSignatureVerifier {
    fn verify(
        &self,
        seat_role: usize,
        epoch_commitment: &ArchivedSeatCommitment,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
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
    archive: &dyn EpochCommitmentArchive,
    sig_verifier: &dyn SeatSignatureVerifier,
) -> Result<FraudVerdict> {
    // 0) Wire-rule validation, before anything else: roles are u32,
    //    1-based, 0 invalid. A role that does not fit is malformed, never
    //    "not found" — a lookup miss would read as an archive anomaly and
    //    smear the chain side for the accuser's encoding error.
    let seat_role_wire: u32 = match evidence.record.seat_role {
        0 => anyhow::bail!("malformed evidence: seat role 0 is invalid (roles are 1-based)"),
        r => u32::try_from(r)
            .map_err(|_| anyhow::anyhow!("malformed evidence: seat role {r} exceeds u32"))?,
    };

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

    // 4) Resolve the record's epoch against the commitment archive. Three
    //    absence outcomes, three different verdicts — before any signature
    //    work, so a time-barred claim never reaches the signature check.
    let epoch_commitment =
        match resolve_epoch(archive, evidence.record.epoch, seat_role_wire) {
            ArchiveResolution::Found(c) => c,
            ArchiveResolution::TimeBarred { oldest_retained } => {
                return Ok(FraudVerdict::NotFraud {
                    why: format!(
                        "time-barred: epoch {} is pruned past the retention horizon \
                         (oldest retained: {}). This is expiry, explicitly NOT a \
                         finding of forgery",
                        evidence.record.epoch, oldest_retained
                    ),
                })
            }
            // Framing resistance: malformed and anomalous evidence ERRORS —
            // it neither convicts the seat nor acquits the evidence.
            ArchiveResolution::NeverExisted { latest } => {
                anyhow::bail!(
                    "malformed evidence: record names epoch {} but the chain has \
                     only established epochs up to {}",
                    evidence.record.epoch,
                    latest
                )
            }
            ArchiveResolution::AnomalousGap => {
                anyhow::bail!(
                    "archive anomaly: epoch {} is within the retained range but has \
                     no commitment for seat {} — refusing to decide either way",
                    evidence.record.epoch,
                    evidence.record.seat_role
                )
            }
        };

    // 4b) Entry binding: the record's header height must not precede the
    //     epoch's keyed height. Malformation errors (framing resistance).
    check_entry_binding(&evidence.record, &epoch_commitment)?;

    // 5) The seat must actually have committed to serving it — verified
    //    against its commitment FOR THE EPOCH THE RECORD NAMES, which is
    //    what keeps epoch-N evidence verifiable after the N+1 reshare.
    let msg = evidence.record.signing_bytes()?;
    if !sig_verifier.verify(
        evidence.record.seat_role,
        &epoch_commitment,
        &msg,
        &evidence.seat_signature,
    ) {
        return Ok(FraudVerdict::NotFraud {
            why: "seat signature does not verify against that epoch's archived \
                  commitment — no proof this seat served the request (framing \
                  attempt or corrupt evidence)"
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

    /// Test double: signature = (signing bytes XOR a per-role byte) ‖ the
    /// commitment text the seat signed under. Verification checks BOTH the
    /// role and that the presented archived commitment matches what was
    /// signed under — which is exactly the property the archive exists for:
    /// a signature made under epoch-N key material verifies against the
    /// epoch-N archive entry and against nothing else.
    struct TestSigner;
    impl TestSigner {
        fn sign(role: usize, commitment_text: &str, msg: &[u8]) -> Vec<u8> {
            let mut out: Vec<u8> = msg.iter().map(|b| b ^ (role as u8)).collect();
            out.extend_from_slice(commitment_text.as_bytes());
            out
        }
    }
    impl SeatSignatureVerifier for TestSigner {
        fn verify(
            &self,
            role: usize,
            epoch_commitment: &ArchivedSeatCommitment,
            msg: &[u8],
            sig: &[u8],
        ) -> bool {
            Self::sign(role, &epoch_commitment.commitment_sha256, msg) == sig
        }
    }

    const HANDLE: &str = "0x13dd2bcf291df94a006996bdfcd9bb8830bbee1218b59d4aa4ec3de2d4502efd";
    const REQUESTER: &str = "0xc000000000000000000000000000000000000003";

    fn record(kind: RequestKind) -> RequestRecord {
        RequestRecord {
            kind,
            handle: HANDLE.into(),
            requester: REQUESTER.into(),
            epoch: 5,
            header_height: 1002,
            seat_role: 3,
        }
    }

    fn evidence(kind: RequestKind, sign_role: usize) -> FraudEvidence {
        let rec = record(kind);
        let sig = TestSigner::sign(
            sign_role,
            &TestArchive::commitment_text(rec.epoch, sign_role),
            &rec.signing_bytes().unwrap(),
        );
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

    /// Test archive: epochs `oldest..=latest`, commitment text derived from
    /// (epoch, role) so a reshare visibly changes every commitment.
    struct TestArchive {
        oldest: u64,
        latest: u64,
    }
    impl TestArchive {
        fn commitment_text(epoch: u64, role: usize) -> String {
            format!("c-{epoch}-{role}")
        }
    }
    impl EpochCommitmentArchive for TestArchive {
        fn bounds(&self) -> (u64, u64) {
            (self.oldest, self.latest)
        }
        fn commitment(&self, epoch: u64, seat_role: u32) -> Option<ArchivedSeatCommitment> {
            ((self.oldest..=self.latest).contains(&epoch)).then(|| ArchivedSeatCommitment {
                commitment_sha256: Self::commitment_text(epoch, seat_role as usize),
                roster_sha256: "roster-genesis".into(),
                // Epoch e keyed at height 100·e in the fixture; the standard
                // test record's header_height (1002) sits comfortably above
                // epoch 5's keyed height (500).
                keyed_height: epoch * 100,
                pk_g_sha256: "pkg-genesis".into(),
            })
        }
    }

    fn archive() -> TestArchive {
        TestArchive {
            oldest: 0,
            latest: 6,
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
            &archive(),
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
            &archive(),
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
            &archive(),
            &TestSigner,
        )
        .unwrap();
        assert!(matches!(v, FraudVerdict::NotFraud { ref why } if why.contains("height")));
    }

    #[test]
    fn malformed_slot_proofs_are_an_error_not_a_conviction() {
        // With root/height matching, step 2 runs — and empty proof layers
        // must ERROR (invalid evidence), never convict.
        let e = verify_fraud(
            &evidence(RequestKind::Reveal, 3),
            trusted_source(),
            &archive(),
            &TestSigner,
        );
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

        // v1 addition: the epoch is in the SIGNED bytes. An unsigned epoch
        // could be re-pointed at a different epoch's archived commitments.
        let mut r = record(RequestKind::Reveal);
        r.epoch = 4;
        assert_ne!(a, r.signing_bytes().unwrap(), "epoch must alter the signed bytes");
        assert!(a.starts_with(b"celar.kms.serve.v1"), "layout change requires the v1 domain");
    }

    #[test]
    fn wrong_seat_signature_is_framing_not_fraud() {
        // Signature made by role 2 presented as role 3's commitment: the
        // signature check must fail — exercises the verifier double directly.
        let rec = record(RequestKind::Reveal);
        let msg = rec.signing_bytes().unwrap();
        let c2 = archive().commitment(rec.epoch, 2).unwrap();
        let c3 = archive().commitment(rec.epoch, 3).unwrap();
        let sig_by_2 = TestSigner::sign(2, &c2.commitment_sha256, &msg);
        assert!(!TestSigner.verify(3, &c3, &msg, &sig_by_2));
        assert!(TestSigner.verify(2, &c2, &msg, &sig_by_2));
    }

    // ---- E23: the archive resolution verdicts ----------------------------

    #[test]
    fn pruned_epoch_is_time_barred_not_forged() {
        // Archive retains 4..=6; the record names epoch 2. Time-barred is a
        // NotFraud VERDICT with the reason stated — never an error, never a
        // forgery finding.
        let mut ev = evidence(RequestKind::Reveal, 3);
        ev.record.epoch = 2;
        ev.seat_signature = TestSigner::sign(
            3,
            &TestArchive::commitment_text(2, 3),
            &ev.record.signing_bytes().unwrap(),
        );
        let arch = TestArchive { oldest: 4, latest: 6 };
        // Reaching step 4 needs valid slot proofs, which these fixtures do
        // not have — so exercise the resolution directly, as the proof-layer
        // tests do for their step.
        match resolve_epoch(&arch, ev.record.epoch, ev.record.seat_role as u32) {
            ArchiveResolution::TimeBarred { oldest_retained } => {
                assert_eq!(oldest_retained, 4)
            }
            _ => panic!("expected TimeBarred, got a different resolution"),
        }
    }

    #[test]
    fn future_epoch_is_malformed_and_anomalous_gap_is_an_error() {
        let arch = archive(); // 0..=6
        assert!(matches!(
            resolve_epoch(&arch, 7, 3),
            ArchiveResolution::NeverExisted { latest: 6 }
        ));
        // In range but absent: a hole the chain should make impossible.
        struct HoleyArchive;
        impl EpochCommitmentArchive for HoleyArchive {
            fn bounds(&self) -> (u64, u64) {
                (0, 6)
            }
            fn commitment(&self, _: u64, _: u32) -> Option<ArchivedSeatCommitment> {
                None
            }
        }
        assert!(matches!(
            resolve_epoch(&HoleyArchive, 5, 3),
            ArchiveResolution::AnomalousGap
        ));
    }

    #[test]
    fn epoch_n_evidence_survives_the_n_plus_1_reshare() {
        // THE E23 regression: the case that silently failed before the
        // archive existed. A seat serves under epoch 5; the committee
        // reshares to epoch 6, every live commitment changes; the epoch-5
        // evidence must STILL verify — against the ARCHIVED epoch-5
        // commitment, not the current one.
        let rec = record(RequestKind::Reveal); // epoch 5, role 3
        let msg = rec.signing_bytes().unwrap();
        let sig = TestSigner::sign(3, &TestArchive::commitment_text(5, 3), &msg);

        // After the reshare the archive spans 0..=6. The epoch-5 entry is
        // retained and unchanged; epoch 6's differs (commitment text derives
        // from the epoch, mirroring reshare.rs's all-commitments-change).
        let arch = archive(); // latest = 6
        let c5 = arch.commitment(5, 3).unwrap();
        let c6 = arch.commitment(6, 3).unwrap();
        assert_ne!(c5, c6, "reshare must have changed the live commitment");

        // Against the archived epoch-5 commitment: verifies.
        assert!(TestSigner.verify(3, &c5, &msg, &sig));

        // Against the CURRENT (epoch-6) commitment: fails — which is
        // exactly what happened to ALL old evidence before the archive,
        // because current state was the only commitment available.
        assert!(
            !TestSigner.verify(3, &c6, &msg, &sig),
            "pre-archive behaviour: epoch-N evidence checked against current \
             commitments — this failing is WHY the archive exists"
        );

        // And the full resolution path picks the archived entry from the
        // record's own epoch field — self-containment.
        match resolve_epoch(&arch, rec.epoch, rec.seat_role as u32) {
            ArchiveResolution::Found(c) => assert_eq!(c, c5),
            _ => panic!("epoch 5 must resolve to its archived commitment"),
        }
    }

    // ---- E31 answers: the entry-binding rules ----------------------------

    #[test]
    fn serving_before_the_epoch_was_keyed_is_malformed() {
        // Record claims service at header height 450 under epoch 5, which
        // the archive says was keyed at height 500. Nothing can be served
        // under a key that did not yet exist — malformed, ERRORS, never a
        // verdict in either direction.
        let mut rec = record(RequestKind::Reveal);
        rec.header_height = 450;
        let entry = archive().commitment(5, 3).unwrap(); // keyed_height 500
        let e = check_entry_binding(&rec, &entry);
        assert!(e.is_err(), "pre-keying service must be malformed: {e:?}");
        assert!(e.unwrap_err().to_string().contains("not keyed until"));

        // At exactly the keyed height and above: fine.
        rec.header_height = 500;
        assert!(check_entry_binding(&rec, &entry).is_ok());
    }

    #[test]
    fn seat_role_zero_is_malformed_not_a_lookup_miss() {
        // Roles are 1-based on the wire; 0 must error as malformed BEFORE
        // any archive lookup — a lookup miss would read as an archive
        // anomaly and smear the chain side for the accuser's encoding error.
        let mut ev = evidence(RequestKind::Reveal, 3);
        ev.record.seat_role = 0;
        let e = verify_fraud(
            &ev,
            trusted_source(),
            &archive(),
            &TestSigner,
        );
        assert!(e.is_err(), "role 0 must be a hard error: {e:?}");
        assert!(e.unwrap_err().to_string().contains("1-based"), "error must name the convention");
    }
}
