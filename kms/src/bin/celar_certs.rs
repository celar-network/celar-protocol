//! celar-certs — TLS certificate generation for the KMS ceremony nodes.
//!
//! Thin passthrough to the upstream generator (`threshold-networking`
//! `tls_certs`, same v0.13.22 pin), so certificates are exactly the shape
//! the mTLS networking stack expects. Example for a 4-party dev ceremony:
//!
//!   celar-certs --ca-prefix party --ca-count 4 -n 1 -o certs
//!
//! Then check `ls certs/` and align `celar-kms-node gen-configs`'s
//! --cert-pattern/--key-pattern/--ca-pattern with the produced names.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    threshold_networking::tls_certs::entry_point().await
}
