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
#[derive(Debug)]
pub struct Polled {
    /// One per executed operation, in canonical order.
    pub attestations: Vec<Attestation>,
    /// Positions this consumer could not follow yet.
    ///
    /// Reported rather than counted, because "nothing to attest here" and
    /// "nothing happened here" are different statements and only one of them
    /// should ever be quiet. Admission carries a commitment and a
    /// data-availability pointer; the body does not ride the stream, so a
    /// consumer cannot execute it until that layer exists.
    pub deferred: Vec<StreamRef>,
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

        for ev in ordered {
            let at = ev.at;
            let decoded = decode(&ev.data).map_err(|err| ServiceError::Decode { at, err })?;

            // §8(ii): execute exactly as emitted, op for op. There is no
            // inspection of the decoded event here — no "this add has a
            // constant operand", no skipping a select with a known predicate.
            // Each would produce a correct value with a different digest, and
            // the fraud game reads that as a cheat.
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
                Outcome::NeedsCiphertextBody { .. } => deferred.push(at),
            }
        }

        Ok(Polled { attestations, deferred })
    }
}
