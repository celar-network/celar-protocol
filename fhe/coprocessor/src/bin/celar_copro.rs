//! Run the consumer against a chain and write what it attests to.
//!
//! Deliberately small. Everything it decides is in the library and tested
//! there; this reads three arguments, dials, and writes a file. A binary that
//! contained judgement would be judgement with no tests.

use std::env;
use std::fs;

use celar_coprocessor::emit::to_json;
use celar_coprocessor::service::Service;
use celar_coprocessor::source::{JsonRpc, RpcSource};

use k256::ecdsa::SigningKey;

/// Blocking HTTP, and nothing else.
struct Http {
    endpoint: String,
}

impl JsonRpc for Http {
    fn call(&self, body: &str) -> Result<String, String> {
        ureq::post(&self.endpoint)
            .set("content-type", "application/json")
            .send_string(body)
            .map_err(|e| format!("{e}"))?
            .into_string()
            .map_err(|e| format!("reading response: {e}"))
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: {} <rpc-endpoint> <chain-id> <from-height> <to-height> <out-file>\n\
             \n\
             Reads the op stream from the chain over the range, executes each\n\
             operation against the pinned backend, signs an attestation for each\n\
             result, and writes them for the relayer to submit.",
            args[0]
        );
        std::process::exit(2);
    }

    let endpoint = args[1].clone();
    let chain_id: u64 = args[2].parse().expect("chain id must be a number");
    let from: u64 = args[3].parse().expect("from height must be a number");
    let to: u64 = args[4].parse().expect("to height must be a number");
    let out = args[5].clone();

    // A fixed development key. Not a production concern yet and said plainly
    // rather than left to be assumed: the identity a coprocessor signs with is
    // what the chain recovers and compares, so where it comes from is a
    // decision that has not been taken.
    let key = SigningKey::from_bytes(&[7u8; 32].into()).expect("fixed dev key");

    // The backend's server key is thread-local state inside the FHE library,
    // so it is armed here, on the thread that will execute.
    let (_ck, sk) = celar_zama::dev_keys();
    tfhe::set_server_key(sk);

    let mut service = Service::new(RpcSource::new(Http { endpoint }), chain_id, key);

    match service.poll(from, to) {
        Ok(polled) => {
            fs::write(&out, to_json(&polled.attestations)).expect("writing the handoff");
            println!(
                "attested {} operation(s), deferred {}, written to {}",
                polled.attestations.len(),
                polled.deferred.len(),
                out
            );
        }
        Err(e) => {
            // The range halted. Printing the whole error matters: it carries
            // the position, which is the diagnosis.
            eprintln!("halted: {e:?}");
            std::process::exit(1);
        }
    }
}
