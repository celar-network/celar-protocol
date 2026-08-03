//! Celar FHE backend — Zama TFHE-rs implementation of the frozen ABI.
//!
//! Scaffold stage: key setup and the encrypted round-trip. The ABI
//! operations are added in the following sub-tasks.

use tfhe::{generate_keys, ClientKey, ConfigBuilder, ServerKey};

/// Crate identity, used by the harness to confirm which backend it loaded.
pub const BACKEND_NAME: &str = "celar-zama-tfhe-rs";

/// Generate a fresh key pair with default parameters.
///
/// Devnet only: the production key is produced by the threshold DKG
/// ceremony and never exists as a single client key.
pub fn dev_keys() -> (ClientKey, ServerKey) {
    generate_keys(ConfigBuilder::default().build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tfhe::prelude::*;
    use tfhe::{set_server_key, FheUint64};

    #[test]
    fn encrypt_decrypt_round_trip() {
        let (ck, _sk) = dev_keys();
        for v in [0u64, 1, 42, u64::MAX] {
            let ct = FheUint64::encrypt(v, &ck);
            let got: u64 = ct.decrypt(&ck);
            assert_eq!(got, v, "round trip failed for {v}");
        }
    }

    #[test]
    fn homomorphic_add_matches_plaintext() {
        let (ck, sk) = dev_keys();
        set_server_key(sk);

        let a = FheUint64::encrypt(1_000_000u64, &ck);
        let b = FheUint64::encrypt(337u64, &ck);
        let sum: u64 = (&a + &b).decrypt(&ck);
        assert_eq!(sum, 1_000_337);

        // silent wrap at the euint64 boundary, per the ABI's sizing note
        let m = FheUint64::encrypt(u64::MAX, &ck);
        let one = FheUint64::encrypt(1u64, &ck);
        let wrapped: u64 = (&m + &one).decrypt(&ck);
        assert_eq!(wrapped, 0);
    }
}
