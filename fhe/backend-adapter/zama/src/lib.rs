//! Celar FHE backend — Zama TFHE-rs implementation of the frozen ABI.
//!
//! Scaffold only at this point: this file exists so the crate compiles and
//! the TFHE-rs dependency is proven to build on the target toolchain.
//! Operations land in the following sub-tasks.

/// Crate identity, used by the harness to confirm which backend it loaded.
pub const BACKEND_NAME: &str = "celar-zama-tfhe-rs";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_builds() {
        assert_eq!(super::BACKEND_NAME, "celar-zama-tfhe-rs");
    }
}
