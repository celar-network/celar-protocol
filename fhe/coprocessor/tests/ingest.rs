//! Ordering and deduplication are properties the consumer owes under every
//! transport, so they are tested against a fixture source rather than a live
//! one. A live source can only show that today's delivery happened to be
//! ordered; a fixture can show that a disordered one is repaired.

use celar_coprocessor::ingest::{canonicalise, IngestError, RawEvent, StreamRef, StreamSource};

fn at(h: u64, tx: u32, log: u32) -> StreamRef {
    StreamRef { height: h, tx_index: tx, log_index: log }
}

fn ev(h: u64, tx: u32, log: u32, byte: u8) -> RawEvent {
    RawEvent { at: at(h, tx, log), data: vec![byte] }
}

struct Fixture(Vec<RawEvent>);

impl StreamSource for Fixture {
    type Error = ();
    fn events(&self, from: u64, to: u64) -> Result<Vec<RawEvent>, ()> {
        Ok(self.0.iter().filter(|e| e.at.height >= from && e.at.height <= to).cloned().collect())
    }
}

#[test]
fn orders_by_height_then_tx_then_log() {
    let shuffled = vec![
        ev(2, 0, 0, b'c'),
        ev(1, 1, 0, b'b'),
        ev(1, 0, 5, b'a'),
    ];
    let out = canonicalise(shuffled).expect("no conflicts here");
    let order: Vec<u8> = out.iter().map(|e| e.data[0]).collect();
    assert_eq!(order, vec![b'a', b'b', b'c']);
}

#[test]
fn at_least_once_delivery_collapses_to_one_execution() {
    let doubled = vec![ev(1, 0, 0, b'x'), ev(1, 0, 0, b'x')];
    let out = canonicalise(doubled).expect("identical repeats are ordinary");
    assert_eq!(out.len(), 1, "a repeated delivery must not execute twice");
}

/// The case worth refusing. Repeats are expected; repeats that disagree mean a
/// reorg or a lying source, and taking the first would mean attesting to
/// whichever arrived first.
#[test]
fn disagreeing_repeats_are_refused_rather_than_chosen_between() {
    let conflicting = vec![ev(1, 0, 0, b'x'), ev(1, 0, 0, b'y')];
    assert_eq!(
        canonicalise(conflicting),
        Err(IngestError::Conflict { at: at(1, 0, 0) })
    );
}

#[test]
fn a_source_is_read_through_the_same_path() {
    let f = Fixture(vec![ev(3, 0, 0, b'c'), ev(1, 0, 0, b'a'), ev(2, 0, 0, b'b')]);
    let out = canonicalise(f.events(1, 2).unwrap()).unwrap();
    let order: Vec<u8> = out.iter().map(|e| e.data[0]).collect();
    assert_eq!(order, vec![b'a', b'b'], "range filter and order, together");
}
