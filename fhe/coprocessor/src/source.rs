//! A live stream source: the chain's own logs, read over JSON-RPC.
//!
//! The protocol calls the subscription channel "a convenience channel, never a
//! trust assumption", and this module is what makes that true rather than
//! aspirational: a consumer that missed events reconstructs them from the chain
//! by range query, and that reconstruction is the definition of correctness the
//! live channel is measured against.
//!
//! # Why the transport is a trait
//!
//! Everything difficult here is parsing: hex widths, a node that ignores a
//! filter, a reorg flag, a field that is absent rather than zero. None of it
//! needs a socket to get wrong, and all of it needs tests. So the HTTP client
//! lives outside and this module is exercised against canned responses - which
//! is also why a live source was deferred in the first place: a live one shows
//! only that today's delivery happened to be well-formed.

use crate::ingest::{RawEvent, StreamRef, StreamSource};
use sha3::{Digest, Keccak256};

/// Hashed to give `topics[0]`. Consumers filter on it; the chain emits it.
///
/// Stated here as the string and hashed, rather than pasted as a digest: a
/// pasted digest is a second record of this constant, and the one thing that
/// could not then be checked is whether the two agree.
pub const STREAM_TOPIC_PREIMAGE: &str = "celar.opstream.v1";

/// The precompile that emits the stream. Fixed by the chain.
pub const PRECOMPILE_ADDRESS: &str = "0x0000000000000000000000000000000000000900";

/// `topics[0]`, as a 0x-prefixed lowercase hex string.
pub fn stream_topic() -> String {
    let mut h = Keccak256::new();
    h.update(STREAM_TOPIC_PREIMAGE.as_bytes());
    format!("0x{}", hex_lower(&h.finalize()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The transport failed. Carries the transport's own message rather than
    /// being interpreted here.
    Transport(String),
    /// The node answered, and the answer was not what was asked for.
    ///
    /// Kept distinct from `Transport` because the two mean opposite things: a
    /// transport failure is retried, and a node returning logs that do not
    /// match the filter is a node this consumer must stop trusting.
    Protocol(String),
    /// A log the chain has since discarded.
    ///
    /// Separate from `Protocol` because it is not a fault. Under CometBFT
    /// finality a committed block is final and this should never appear - which
    /// is exactly why it is refused loudly rather than skipped. An unexplained
    /// one is a signal about the chain, not noise to filter out, and attesting
    /// to an operation that did not happen is the one thing a coprocessor must
    /// never do.
    Removed { at: StreamRef },
}

/// The transport seam. One method, one string in, one string out.
pub trait JsonRpc {
    fn call(&self, body: &str) -> Result<String, String>;
}

/// Reads the op stream from an execution-layer JSON-RPC endpoint.
pub struct RpcSource<T: JsonRpc> {
    transport: T,
}

impl<T: JsonRpc> RpcSource<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: JsonRpc> StreamSource for RpcSource<T> {
    type Error = SourceError;

    fn events(&self, from_height: u64, to_height: u64) -> Result<Vec<RawEvent>, SourceError> {
        let body = get_logs_request(from_height, to_height);
        let raw = self.transport.call(&body).map_err(SourceError::Transport)?;
        parse_logs_response(&raw)
    }
}

/// The request, built as a string rather than through a serialiser.
///
/// It has four fixed fields and no user-supplied text, so a serialiser would
/// add a dependency and a layer without removing a failure mode.
pub fn get_logs_request(from_height: u64, to_height: u64) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{{"fromBlock":"0x{:x}","toBlock":"0x{:x}","address":"{}","topics":["{}"]}}]}}"#,
        from_height,
        to_height,
        PRECOMPILE_ADDRESS,
        stream_topic()
    )
}

/// Turns a response into events, refusing anything it cannot account for.
///
/// Every refusal below is a case where skipping would be worse than stopping:
/// a consumer that silently drops one event attests to a stream the chain did
/// not emit, and the fraud game cannot tell that from dishonesty.
pub fn parse_logs_response(raw: &str) -> Result<Vec<RawEvent>, SourceError> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| SourceError::Protocol(format!("not json: {e}")))?;

    if let Some(err) = v.get("error") {
        return Err(SourceError::Protocol(format!("rpc error: {err}")));
    }

    let logs = v
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| SourceError::Protocol("no result array".into()))?;

    let want_topic = stream_topic();
    let mut out = Vec::with_capacity(logs.len());

    for (i, log) in logs.iter().enumerate() {
        // A node that answered with logs outside the filter is not one whose
        // answers can be trusted for the ones inside it either.
        let addr = str_field(log, "address", i)?;
        if !addr.eq_ignore_ascii_case(PRECOMPILE_ADDRESS) {
            return Err(SourceError::Protocol(format!(
                "log {i}: address {addr} is outside the requested filter"
            )));
        }
        let topic0 = log
            .get("topics")
            .and_then(|t| t.as_array())
            .and_then(|t| t.first())
            .and_then(|t| t.as_str())
            .ok_or_else(|| SourceError::Protocol(format!("log {i}: no topics[0]")))?;
        if !topic0.eq_ignore_ascii_case(&want_topic) {
            return Err(SourceError::Protocol(format!(
                "log {i}: topic {topic0} is outside the requested filter"
            )));
        }

        let at = StreamRef {
            height: hex_u64(log, "blockNumber", i)?,
            tx_index: hex_u64(log, "transactionIndex", i)? as u32,
            log_index: hex_u64(log, "logIndex", i)? as u32,
        };

        // Checked after the position is known, so the refusal can name it.
        if log.get("removed").and_then(|r| r.as_bool()) == Some(true) {
            return Err(SourceError::Removed { at });
        }

        let data = str_field(log, "data", i)?;
        let bytes = decode_hex(data)
            .ok_or_else(|| SourceError::Protocol(format!("log {i}: data is not hex")))?;

        out.push(RawEvent { at, data: bytes });
    }

    // Ordering and deduplication are NOT done here, deliberately: they are the
    // consumer's obligation under every source, they already have an
    // implementation and tests, and doing them twice in two places is how the
    // two would eventually disagree.
    Ok(out)
}

fn str_field<'a>(log: &'a serde_json::Value, name: &str, i: usize) -> Result<&'a str, SourceError> {
    log.get(name)
        .and_then(|x| x.as_str())
        .ok_or_else(|| SourceError::Protocol(format!("log {i}: no {name}")))
}

/// Reads a quantity field.
///
/// Absent is an error rather than zero. A missing `logIndex` read as 0 would
/// silently collide with the first log in the block, and the position is what
/// the signature commits to.
fn hex_u64(log: &serde_json::Value, name: &str, i: usize) -> Result<u64, SourceError> {
    let s = str_field(log, name, i)?;
    let body = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(body, 16)
        .map_err(|_| SourceError::Protocol(format!("log {i}: {name} = {s} is not a quantity")))
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    if body.len() % 2 != 0 {
        return None;
    }
    (0..body.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&body[i..i + 2], 16).ok())
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
