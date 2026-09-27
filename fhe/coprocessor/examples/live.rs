//! Runs the coprocessor against a live chain.
//!
//! The library has no transport by design: `JsonRpc` is a seam so the decoder
//! and the executor can be tested without a network. This example supplies the
//! missing half — twenty lines of TcpStream rather than an HTTP dependency,
//! because it dials one known localhost endpoint and nothing else.
//!
//! Usage:  cargo run --example live -- [from_block] [to_block]

use std::io::{Read, Write};
use std::net::TcpStream;

use celar_coprocessor::attest::Attestation;
use celar_coprocessor::service::Service;
use celar_coprocessor::source::{JsonRpc, RpcSource};
use k256::ecdsa::SigningKey;
use tfhe::set_server_key;

struct Http {
    addr: String,
}

impl JsonRpc for Http {
    fn call(&self, body: &str) -> Result<String, String> {
        let mut s = TcpStream::connect(&self.addr).map_err(|e| e.to_string())?;
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.addr,
            body.len(),
            body
        );
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut out = String::new();
        s.read_to_string(&mut out).map_err(|e| e.to_string())?;
        let (head, body) = out
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("no body in response: {out}"))?;

        // Small replies arrive with Content-Length; a large eth_getLogs arrives
        // chunked, and its body starts with a hex length rather than `{`. The
        // failure reads as "not json", which points at the node rather than at
        // this client.
        if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            let mut rest = body;
            let mut whole = String::new();
            loop {
                let (size_line, tail) = rest
                    .split_once("\r\n")
                    .ok_or_else(|| "truncated chunk header".to_string())?;
                let size = usize::from_str_radix(size_line.trim(), 16)
                    .map_err(|e| format!("bad chunk size {size_line:?}: {e}"))?;
                if size == 0 {
                    break;
                }
                if tail.len() < size {
                    return Err("truncated chunk body".to_string());
                }
                whole.push_str(&tail[..size]);
                rest = &tail[size..];
                rest = rest.strip_prefix("\r\n").unwrap_or(rest);
            }
            return Ok(whole);
        }
        Ok(body.trim().to_string())
    }
}

fn number(http: &Http, method: &str) -> u64 {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":[]}}"#);
    let raw = http.call(&body).unwrap_or_else(|e| panic!("{method}: {e}"));
    let v: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{method} returned non-json ({e}): {raw}"));
    let hex = v["result"].as_str().unwrap_or_else(|| panic!("{method}: {raw}"));
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("hex")
}

fn main() {
    // The server key is thread-local in TFHE, so it must be armed on the thread
    // that executes. Without this every operation fails, and the failure looks
    // like a decoding problem rather than a missing key.
    let (_ck, sk) = celar_zama::dev_keys();
    set_server_key(sk);

    let addr = "127.0.0.1:8545".to_string();
    let probe = Http { addr: addr.clone() };

    let chain_id = number(&probe, "eth_chainId");
    let latest = number(&probe, "eth_blockNumber");

    let args: Vec<String> = std::env::args().collect();
    let from: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let to: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(latest);

    println!("chain id {chain_id}, head {latest}, polling {from}..={to}");

    // A dev key. Attestations from this run are not meant to verify against any
    // roster; what is being tested is that the chain's own stream decodes,
    // executes and digests, not who signed the result.
    let key = SigningKey::from_slice(&[0x11u8; 32]).expect("dev key");
    let mut service = Service::new(RpcSource::new(Http { addr }), chain_id, key);

    match service.poll(from, to) {
        Ok(polled) => {
            println!(
                "attested {} operation(s), deferred {}",
                polled.attestations.len(),
                polled.deferred.len()
            );
            for r in &polled.deferred {
                println!("  deferred at {r:?}");
            }
            for a in &polled.attestations {
                println!("  {a:?}");
            }

            // Written where the chain side can read it. The point is not that
            // Rust can serialise: it is that the Go verifier reconstructs the
            // same preimage from the same fields and recovers the same signer.
            // Both sides pass their own tests and agree with a hand-written
            // vector; neither has met the other's output from a real chain.
            let out = std::path::Path::new("../../testdata/attestation/live-devnet.json");
            if let Some(dir) = out.parent() {
                std::fs::create_dir_all(dir).expect("create testdata dir");
            }
            std::fs::write(out, vector_json(chain_id, &polled.attestations))
                .expect("write vector");
            println!("wrote {}", out.display());
        }
        Err(e) => {
            // The position is the point. A failure without one leaves you
            // hunting which of several identical operations it was.
            println!("poll failed: {e:?}");
            std::process::exit(1);
        }
    }
}

/// Unprefixed lowercase hex, chain id alongside — the preimage binds it, so a
/// vector without it cannot be checked by the other side.
fn vector_json(chain_id: u64, attestations: &[Attestation]) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"chain_id\": {chain_id},\n"));
    out.push_str("  \"attestations\": [\n");
    for (i, a) in attestations.iter().enumerate() {
        out.push_str("    {\n");
        out.push_str(&format!("      \"height\": {},\n", a.at.height));
        out.push_str(&format!("      \"tx_index\": {},\n", a.at.tx_index));
        out.push_str(&format!("      \"log_index\": {},\n", a.at.log_index));
        out.push_str(&format!("      \"result_handle\": \"{}\",\n", hex::encode(a.result_handle)));
        out.push_str(&format!("      \"ct_digest\": \"{}\",\n", hex::encode(a.ct_digest)));
        out.push_str(&format!("      \"env_version\": {},\n", a.env_version));
        out.push_str(&format!("      \"coprocessor_id\": \"{}\",\n", hex::encode(a.coprocessor_id)));
        out.push_str(&format!("      \"signature\": \"{}\"\n", hex::encode(&a.signature)));
        out.push_str(if i + 1 == attestations.len() { "    }\n" } else { "    },\n" });
    }
    out.push_str("  ]\n}\n");
    out
}
