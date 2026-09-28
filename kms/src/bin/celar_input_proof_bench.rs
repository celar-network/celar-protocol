//! Input-proof candidate measurement: TFHE-rs zk-pok (proof of correct
//! encryption under the compact public key), timed end to end.
//!
//! The admission path needs a proof that a submitted ciphertext is a correct
//! encryption AND that the proof is bound to its submission context, so a
//! copied proof fails verification anywhere but its original context. TFHE-rs
//! ships exactly this shape natively: `ProvenCompactCiphertextList` proves
//! correct encryption under the compact public key, and the proof binds
//! caller-supplied METADATA bytes — verification with different metadata
//! fails. The admission envelope (chain id ‖ target ‖ submitter ‖ tx-scope ‖
//! expiry) rides as that metadata, which is precisely the required tuple.
//!
//! This bench measures the full lifecycle at the admission shape (one u64):
//! CRS generation, proving (client-side), verification (the chain-side cost
//! that decides where verification runs), and artifact sizes — for both
//! compute-load profiles. The numbers feed the proof-system selection and the
//! verifier-integration comparison; nothing here wires into the chain.
//!
//! Run: cargo run --release --bin celar_input_proof_bench -- --params test
//! (production crypto parameters: --params nist; substantially heavier).

use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{ProvenCompactCiphertextList, Tag};
use threshold_execution::tfhe_internals::parameters::{
    DKGParams, NIST_PARAMS_P32_SNS_FGLWE, PARAMS_TEST_BK_SNS,
};

#[derive(Parser)]
struct Args {
    /// Parameter set: test | nist
    #[arg(long, default_value = "test")]
    params: String,
    /// Max plaintext bits the CRS supports (64 = one euint64 admission).
    #[arg(long, default_value_t = 64)]
    max_bits: usize,
    /// Timed proving/verification iterations (after one warm-up).
    #[arg(long, default_value_t = 5)]
    iters: usize,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dkg_params: DKGParams = match args.params.as_str() {
        "test" => PARAMS_TEST_BK_SNS,
        "nist" => NIST_PARAMS_P32_SNS_FGLWE,
        other => anyhow::bail!("unknown --params {other:?} (expected test | nist)"),
    };

    // Config exactly as the upstream service builds it from DKG parameters —
    // the same parameter path a ceremony-produced compact key comes from.
    let config = if dkg_params.has_dedicated_compact_pk_params() {
        tfhe::ConfigBuilder::with_custom_parameters(dkg_params.classic_pbs())
            .use_dedicated_compact_public_key_parameters(
                dkg_params
                    .dedicated_pk_params()
                    .context("params claim dedicated compact-pk params but supply none")?,
            )
            .build()
    } else {
        tfhe::ConfigBuilder::with_custom_parameters(dkg_params.classic_pbs()).build()
    };

    // CRS: the public reference string proofs verify against. Generated
    // locally here (a development CRS — nothing ships on one); the upstream
    // engine has a distributed ceremony for the production CRS.
    let t0 = Instant::now();
    let crs = CompactPkeCrs::from_config(config, args.max_bits)
        .map_err(|e| anyhow::anyhow!("CRS generation: {e:?}"))?;
    let crs_secs = t0.elapsed().as_secs_f64();
    let crs_bytes = bincode::serialize(&crs).context("serializing CRS")?.len();

    // Compact public key on the same parameter path.
    let (pk, sk_note) = if dkg_params.has_dedicated_compact_pk_params() {
        let csk = tfhe::integer::public_key::CompactPrivateKey::new(
            dkg_params.compact_pk_enc_params(),
        );
        let pk = tfhe::integer::public_key::CompactPublicKey::new(&csk);
        (
            tfhe::CompactPublicKey::from_raw_parts(pk, Tag::default()),
            "dedicated compact-pk params",
        )
    } else {
        let cks = tfhe::integer::ClientKey::new(dkg_params.classic_pbs());
        let raw = cks.into_raw_parts();
        let pk = tfhe::shortint::CompactPublicKey::new(&raw);
        let pk = tfhe::integer::CompactPublicKey::from_raw_parts(pk);
        (
            tfhe::CompactPublicKey::from_raw_parts(pk, Tag::default()),
            "compact pk from classic params",
        )
    };
    let pk_bytes = bincode::serialize(&pk).context("serializing pk")?.len();

    // The admission envelope shape as metadata: 89 bytes, same layout the
    // precompile parses (version ‖ chain id ‖ target ‖ submitter ‖ tx-scope ‖
    // expiry). Contents are arbitrary here; only the size and the binding
    // behaviour matter to the measurement.
    let metadata: Vec<u8> = (0..89u8).collect();
    let value: u64 = 42;

    println!(
        "params={} ({sk_note}) max_bits={} iters={}",
        args.params, args.max_bits, args.iters
    );
    println!("crs: gen {crs_secs:.2}s, {crs_bytes} bytes; pk: {pk_bytes} bytes");

    for load in [ZkComputeLoad::Proof, ZkComputeLoad::Verify] {
        // Warm-up (excluded), then timed iterations.
        let prove = |m: &[u8]| -> Result<ProvenCompactCiphertextList> {
            let mut b = ProvenCompactCiphertextList::builder(&pk);
            b.push(value);
            b.build_with_proof_packed(&crs, m, load)
                .map_err(|e| anyhow::anyhow!("prove: {e:?}"))
        };
        let warm = prove(&metadata)?;
        let proof_bytes = bincode::serialize(&warm).context("serializing proof")?.len();

        let mut prove_s = Vec::new();
        let mut verify_s = Vec::new();
        for _ in 0..args.iters {
            let t = Instant::now();
            let proven = prove(&metadata)?;
            prove_s.push(t.elapsed().as_secs_f64());

            let t = Instant::now();
            let ok = proven.verify(&crs, &pk, &metadata).is_valid();
            verify_s.push(t.elapsed().as_secs_f64());
            anyhow::ensure!(ok, "honest proof failed verification");
        }

        // The binding property, asserted rather than assumed: the same proof
        // under DIFFERENT metadata must fail — this is what makes a copied
        // proof dead outside its submission context.
        let mut tampered = metadata.clone();
        tampered[30] ^= 0x01; // one bit of the submitter field
        anyhow::ensure!(
            !warm.verify(&crs, &pk, &tampered).is_valid(),
            "proof verified under altered metadata — the binding does not hold"
        );

        let avg = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
        println!(
            "load={:?}: prove avg {:.3}s, verify avg {:.3}s (n={}), proof {} bytes, metadata-binding holds",
            load,
            avg(&prove_s),
            avg(&verify_s),
            args.iters,
            proof_bytes,
        );
    }

    Ok(())
}
