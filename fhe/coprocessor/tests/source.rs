//! The live source, tested against canned responses.
//!
//! Every case here is a way a node can answer plausibly and wrongly. None of
//! them needs a socket, and a live endpoint would exercise exactly one of
//! them — the happy path — while looking like it had tested the rest.

use celar_coprocessor::ingest::{StreamRef, StreamSource};
use celar_coprocessor::source::{
    get_logs_request, parse_logs_response, stream_topic, JsonRpc, RpcSource, SourceError,
    PRECOMPILE_ADDRESS,
};

fn log(height: &str, tx: &str, idx: &str, data: &str) -> String {
    format!(
        r#"{{"address":"{}","topics":["{}"],"data":"{}","blockNumber":"{}","transactionIndex":"{}","logIndex":"{}","removed":false}}"#,
        PRECOMPILE_ADDRESS,
        stream_topic(),
        data,
        height,
        tx,
        idx
    )
}

fn response(logs: &[String]) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"result":[{}]}}"#, logs.join(","))
}

#[test]
fn the_request_names_the_filter_the_chain_emits_under() {
    let body = get_logs_request(7, 9);
    assert!(body.contains(r#""fromBlock":"0x7""#), "{body}");
    assert!(body.contains(r#""toBlock":"0x9""#), "{body}");
    assert!(body.contains(PRECOMPILE_ADDRESS), "{body}");
    // The topic is hashed from its preimage rather than pasted, so this also
    // asserts the two cannot drift apart.
    assert!(body.contains(&stream_topic()), "{body}");
}

#[test]
fn parses_position_and_payload() {
    let r = response(&[log("0x2a", "0x1", "0x3", "0xdeadbeef")]);
    let events = parse_logs_response(&r).expect("well-formed response");

    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].at,
        StreamRef { height: 42, tx_index: 1, log_index: 3 }
    );
    assert_eq!(events[0].data, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn refuses_a_log_outside_the_requested_address() {
    // A node ignoring the filter is not one to be trusted for the logs that
    // did match it either.
    let bad = format!(
        r#"{{"address":"0x000000000000000000000000000000000000dead","topics":["{}"],"data":"0x00","blockNumber":"0x1","transactionIndex":"0x0","logIndex":"0x0","removed":false}}"#,
        stream_topic()
    );
    match parse_logs_response(&response(&[bad])) {
        Err(SourceError::Protocol(m)) => assert!(m.contains("outside the requested filter"), "{m}"),
        other => panic!("a foreign address must be refused, got {other:?}"),
    }
}

#[test]
fn refuses_a_log_under_a_different_topic() {
    let bad = format!(
        r#"{{"address":"{}","topics":["0x{}"],"data":"0x00","blockNumber":"0x1","transactionIndex":"0x0","logIndex":"0x0","removed":false}}"#,
        PRECOMPILE_ADDRESS,
        "11".repeat(32)
    );
    match parse_logs_response(&response(&[bad])) {
        Err(SourceError::Protocol(m)) => assert!(m.contains("outside the requested filter"), "{m}"),
        other => panic!("a foreign topic must be refused, got {other:?}"),
    }
}

#[test]
fn refuses_a_removed_log_and_names_its_position() {
    // Under this chain's finality a committed block is final, so this should
    // never appear. That is why it is refused rather than skipped: an
    // unexplained one is a statement about the chain.
    let removed = format!(
        r#"{{"address":"{}","topics":["{}"],"data":"0x00","blockNumber":"0x5","transactionIndex":"0x2","logIndex":"0x1","removed":true}}"#,
        PRECOMPILE_ADDRESS,
        stream_topic()
    );
    match parse_logs_response(&response(&[removed])) {
        Err(SourceError::Removed { at }) => assert_eq!(
            at,
            StreamRef { height: 5, tx_index: 2, log_index: 1 }
        ),
        other => panic!("a reorged log must be refused, got {other:?}"),
    }
}

#[test]
fn refuses_a_missing_position_field_rather_than_defaulting_it() {
    // The failure this guards: a missing logIndex read as 0 collides with the
    // first log in the block, and the position is what the signature commits
    // to — so the collision would surface as an unverifiable attestation,
    // nowhere near the cause.
    let partial = format!(
        r#"{{"address":"{}","topics":["{}"],"data":"0x00","blockNumber":"0x5","transactionIndex":"0x2","removed":false}}"#,
        PRECOMPILE_ADDRESS,
        stream_topic()
    );
    match parse_logs_response(&response(&[partial])) {
        Err(SourceError::Protocol(m)) => assert!(m.contains("logIndex"), "{m}"),
        other => panic!("a missing position field must be refused, got {other:?}"),
    }
}

#[test]
fn refuses_an_rpc_error_rather_than_reading_an_empty_result() {
    let r = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"limit exceeded"}}"#;
    match parse_logs_response(r) {
        Err(SourceError::Protocol(m)) => assert!(m.contains("limit exceeded"), "{m}"),
        other => panic!("an error response must not read as zero events, got {other:?}"),
    }
}

#[test]
fn an_empty_range_is_not_an_error() {
    let events = parse_logs_response(&response(&[])).expect("empty is legitimate");
    assert!(events.is_empty());
}

struct Canned(String);
impl JsonRpc for Canned {
    fn call(&self, _body: &str) -> Result<String, String> {
        Ok(self.0.clone())
    }
}

struct Broken;
impl JsonRpc for Broken {
    fn call(&self, _body: &str) -> Result<String, String> {
        Err("connection refused".into())
    }
}

#[test]
fn the_source_reads_through_the_transport() {
    let src = RpcSource::new(Canned(response(&[log("0x1", "0x0", "0x0", "0xaa")])));
    let events = src.events(1, 1).expect("canned response");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data, vec![0xaa]);
}

#[test]
fn a_transport_failure_is_distinct_from_a_protocol_failure() {
    // The two demand opposite responses: retry the first, stop trusting the
    // node on the second. Collapsing them would make a broken endpoint look
    // like a hostile one and vice versa.
    let src = RpcSource::new(Broken);
    match src.events(1, 1) {
        Err(SourceError::Transport(m)) => assert!(m.contains("connection refused"), "{m}"),
        other => panic!("expected a transport error, got {other:?}"),
    }
}
