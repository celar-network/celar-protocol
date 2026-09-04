//! The op-stream consumer.
//!
//! The protocol writes its obligations on this side: execute the stream
//! exactly as emitted, op for op, and attest to each result. Until a consumer
//! exists those obligations bind nobody, which is why this crate is the other
//! half of the fraud game rather than an optional client.

pub mod attest;
pub mod exec;
pub mod ingest;
pub mod opstream;
