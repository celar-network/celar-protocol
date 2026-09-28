//! The service loop: ingest, execute, attest.
//!
//! Each half of this has been tested alone for weeks. This is where they meet,
//! and the meeting is the point — a decoder that reads the chain's bytes and an
//! executor that runs them are two documents agreeing until something drives
//! one from the other.
//!
//! # What this deliberately does not do
//!
//! Submit. Producing an attestation and getting it into chain state are
//! different problems: the second needs a transaction, a key with a balance and
//! a nonce, and none of that belongs in the thing that decides what is true.
//! Returning the attestations lets the caller choose, and keeps this testable
//! without a chain.

use sha3::{Digest, Keccak256};

use crate::attest::Attestation;
use crate::exec::{ExecError, Executor, Outcome};
use crate::ingest::{canonicalise, IngestError, StreamRef, StreamSource};
use crate::opstream::{decode, DecodeError};
use crate::sign::sign_attestation;

use k256::ecdsa::SigningKey;

/// What one poll produced.
/// One abort, as reported by the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abort {
    /// Where the abort event itself sits.
    pub at: StreamRef,
    /// The position of the op that died.
    pub aborted_at: StreamRef,
    /// That op's chain-assigned handle, from the abort's `resultHandle`.
    pub aborted_handle: [u8; 32],
}

#[derive(Debug)]
pub struct Polled {
    /// One per executed operation, in canonical order.
    pub attestations: Vec<Attestation>,
    /// Aborts the chain reported in this range, in canonical order.
    pub aborts: Vec<Abort>,
    /// Positions this consumer could not follow yet.
    ///
    /// Reported rather than counted, because "nothing to attest here" and
    /// "nothing happened here" are different statements and only one of them
    /// should ever be quiet. Admission carries a commitment and a
    /// data-availability pointer; the body does not ride the stream, so a
    /// consumer cannot execute it until that layer exists.
    pub deferred: Vec<Deferred>,
}

/// One position this consumer did not execute, and why it did not.
///
/// The reason is carried rather than implied. "Deferred" alone collapses two
/// different situations — a body that has not arrived and an operand whose
/// producer died — and only one of them ever resolves by waiting for a data
/// layer that does not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deferred {
    pub at: StreamRef,
    pub reason: DeferReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferReason {
    /// Admission: the commitment and the availability pointer are on the
    /// stream, the ciphertext body is not, and no data-availability layer
    /// exists to fetch it from.
    CiphertextBodyUnavailable,
    /// An operand's producing op was aborted by the chain. The operand is
    /// PENDING, not missing: §6 says the chain reassigns, so the value is
    /// expected to arrive at a later position rather than never.
    OperandPending { handle: [u8; 32] },
}

#[derive(Debug)]
pub enum ServiceError<E> {
    Source(E),
    Ingest(IngestError),
    /// Both carry the position. An error without one is nearly useless here:
    /// the stream is ordered, so the FIRST failing position is the whole
    /// diagnosis, and a message naming only the opcode leaves the reader
    /// hunting for which of several identical ops it was.
    Decode { at: StreamRef, err: DecodeError },
    Exec { at: StreamRef, err: ExecError },
    Digest { at: StreamRef },
}

pub struct Service<S: StreamSource> {
    source: S,
    executor: Executor,
    chain_id: u64,
    key: SigningKey,
}

impl<S: StreamSource> Service<S> {
    pub fn new(source: S, chain_id: u64, key: SigningKey) -> Self {
        Self { source, executor: Executor::new(), chain_id, key }
    }

    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Consume one height range.
    ///
    /// # Why this halts rather than skipping
    ///
    /// The stream is a dependency chain: an op's operands are earlier results.
    /// Skipping a failure and continuing means executing later ops against
    /// operands that were never produced — which either errors somewhere
    /// unrelated or, worse, succeeds against a stale handle and attests to a
    /// computation the chain never described. So the first failure stops the
    /// range, with its position.
    pub fn poll(&mut self, from_height: u64, to_height: u64) -> Result<Polled, ServiceError<S::Error>> {
        let raw = self
            .source
            .events(from_height, to_height)
            .map_err(ServiceError::Source)?;

        // Ordering and deduplication before anything is executed, not after.
        let ordered = canonicalise(raw).map_err(ServiceError::Ingest)?;

        let mut attestations = Vec::new();
        let mut deferred = Vec::new();
        let mut aborts = Vec::new();

        // Handles whose producing op the chain aborted, plus handles produced
        // by ops we deferred because of one. Membership means PENDING, not
        // missing: §6 has the chain reassign, so the value is expected later at
        // another position.
        //
        // Deferral has to propagate. An op whose operand is pending cannot
        // execute, and its own result is then pending for the same reason — so
        // a whole dependent subgraph defers rather than one op.
        let mut pending: std::collections::HashSet<[u8; 32]> = Default::default();

        for ev in ordered {
            let at = ev.at;
            let decoded = decode(&ev.data).map_err(|err| ServiceError::Decode { at, err })?;

            // §8(ii): execute exactly as emitted, op for op. There is no
            // inspection of the decoded event here — no "this add has a
            // constant operand", no skipping a select with a known predicate.
            // Each would produce a correct value with a different digest, and
            // the fraud game reads that as a cheat.
            // Checked BEFORE executing, not after. The executor would refuse a
            // pending operand as an unknown handle, which is the right refusal
            // with the wrong reason: unknown means never seen, pending means
            // seen and coming. Reporting the first would send a reader looking
            // for a decode fault that is not there.
            if let Some(h) = decoded.operands.iter().find(|h| pending.contains(*h)) {
                deferred.push(Deferred {
                    at,
                    reason: DeferReason::OperandPending { handle: **&h },
                });
                pending.insert(decoded.result_handle);
                continue;
            }

            let outcome = self
                .executor
                .execute(&decoded)
                .map_err(|err| ServiceError::Exec { at, err })?;

            match outcome {
                Outcome::Executed(backend_handle) => {
                    let basis = self
                        .executor
                        .backend()
                        .digest_basis(backend_handle)
                        .map_err(|_| ServiceError::Digest { at })?;

                    let mut h = Keccak256::new();
                    h.update(&basis);
                    let ct_digest: [u8; 32] = h.finalize().into();

                    attestations.push(sign_attestation(
                        &self.key,
                        self.chain_id,
                        &at,
                        &decoded.result_handle,
                        &ct_digest,
                    ));
                }
                Outcome::NeedsCiphertextBody { .. } => {
                    deferred.push(Deferred {
                        at,
                        reason: DeferReason::CiphertextBodyUnavailable,
                    });
                    pending.insert(decoded.result_handle);
                }
                Outcome::Aborted { aborted_at, aborted_handle } => {
                    // CONTINUE past the abort. Halting here would make one
                    // aborted op stop consumption of everything behind it in
                    // the range — which is a stalling coprocessor, the exact
                    // thing §6's pattern exists to prevent.
                    aborts.push(Abort { at, aborted_at, aborted_handle });
                    pending.insert(aborted_handle);
                }
            }
        }

        Ok(Polled { attestations, deferred, aborts })
    }
}
