//! Celar FHE backend — Zama TFHE-rs implementation of the frozen ABI.

pub mod backend;
#[cfg(feature = "python")]
pub mod python;

use tfhe::{generate_keys, ClientKey, ConfigBuilder, ServerKey};

pub use backend::{Backend, FheError, Handle};

/// Crate identity, used by the harness to confirm which backend it loaded.
pub const BACKEND_NAME: &str = "celar-zama-tfhe-rs";

/// Generate a fresh key pair with default parameters.
///
/// Devnet only: the production key is produced by the threshold DKG
/// ceremony and never exists as a single client key.
pub fn dev_keys() -> (ClientKey, ServerKey) {
    generate_keys(ConfigBuilder::default().build())
}
