//! Ingestion: getting events in the order the chain committed them.
//!
//! Two obligations sit here rather than in the decoder.
//!
//! Ordering. The canonical order is (height, txIndex, logIndex), and a
//! consumer that executes out of order computes from operands that did not
//! exist yet.
//!
//! Deduplication. Delivery is at-least-once, so the same event can arrive
//! twice and must collapse to one execution.
//!
//! The transport is explicitly not a trust assumption: a consumer that missed
//! events reconstructs them from the chain. So this module is written against
//! a source trait, and the live channel is one implementation of it rather
//! than the definition of correctness.

use std::collections::BTreeMap;

/// Where an event sits in the canonical order.
///
/// Field order is the sort order, which is why the derive is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamRef {
    pub height: u64,
    pub tx_index: u32,
    pub log_index: u32,
}

/// One event as delivered: its position, and the bytes the decoder will read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    pub at: StreamRef,
    pub data: Vec<u8>,
}

/// Anywhere events can come from: a live subscription, an archive node, a
/// fixture. Ordering and deduplication are the consumer's job under every one
/// of them, which is why they live here and not in the transport.
pub trait StreamSource {
    type Error;
    fn events(&self, from_height: u64, to_height: u64) -> Result<Vec<RawEvent>, Self::Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngestError {
    /// The same position delivered twice with different bytes.
    ///
    /// At-least-once delivery makes repeats ordinary; repeats that DISAGREE
    /// are not. Taking the first and moving on would mean attesting to
    /// whichever copy arrived first, so this refuses instead.
    Conflict { at: StreamRef },
}

/// Sorts into canonical order and collapses duplicates.
///
/// Returns an error rather than a choice when two deliveries claim the same
/// position with different content.
pub fn canonicalise(events: Vec<RawEvent>) -> Result<Vec<RawEvent>, IngestError> {
    let mut by_ref: BTreeMap<StreamRef, RawEvent> = BTreeMap::new();
    for e in events {
        match by_ref.get(&e.at) {
            Some(seen) if seen.data != e.data => return Err(IngestError::Conflict { at: e.at }),
            Some(_) => {}
            None => {
                by_ref.insert(e.at, e);
            }
        }
    }
    Ok(by_ref.into_values().collect())
}
