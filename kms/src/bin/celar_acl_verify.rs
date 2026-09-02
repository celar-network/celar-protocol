//! celar-acl-verify — the ACL read-path spike: verify a proof of Celar ACL state
//! against a devnet commitment, KMS-side.
//!
//!   celar-acl-verify slots  --handle 0x… --grantee 0x…
//!   celar-acl-verify verify --proof proof.json --header header.json \
//!                           --allow-unverified-header [--block block.json] \
//!                           --handle 0x… --grantee 0x… --perm reencrypt-to-self
//!
//! TRUST BOUNDARY: --header/--app-hash roots are caller-supplied and NOT
//! light-client-verified — REFUSED by default; the dev flag admits them and
//! taints the verdict (`root=UNVERIFIED-DEV`). The KMS trust path only
//! accepts `AppHashSource::LightClientVerified` (see `header_trust`).
//!
//! `proof.json`  = eth_getProof response for the precompile account with the
//!                 two slots printed by `slots`, fetched at EVM block H
//! `header.json` = CometBFT `/header?height=H+1` response (AppHash source)
//! `block.json`  = eth_getBlockByNumber response (optional; H cross-check)
//!
//! Two verification formats, auto-detected from the proof bytes:
//!
//! * **ics23** (what `cosmos/evm` v0.7.0 actually serves — ACL proof-format finding
//!   2026-08-15): each storage slot carries [iavl, multistore] protobuf
//!   proofs; chain = AppHash ⊢ store "evm" root ⊢ 0x02‖addr‖slot. The
//!   trusted root is the CometBFT **AppHash at height H+1** (AppHash at N
//!   commits state after block N−1). The EVM RPC's `stateRoot`/`storageHash`
//!   are NOT usable commitments on this chain.
//! * **mpt** (geth-style EIP-1186, kept for reference/tests):
//!   stateRoot ⊢ account 0x…0900 → storageRoot ⊢ the two slots.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::Value;

use celar_kms::acl::{
    acl_slot, decode_meta, has_perm, meta_slot, perm_bit, FHE_PRECOMPILE_ADDRESS,
};
use celar_kms::header_trust::{AppHashSource, TrustPolicy};
use celar_kms::ics23_verify::{self, SlotOutcome};
use celar_kms::mpt::{keccak256, storage_word, verify_proof, ProofOutcome};

#[derive(Parser)]
#[command(name = "celar-acl-verify", version, about = "Celar KMS — ACL state-proof verifier")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the two storage slots to request from eth_getProof.
    Slots {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        grantee: String,
    },
    /// Verify the fetched proofs against the chain commitment.
    Verify {
        /// eth_getBlockByNumber response. Required for mpt; optional
        /// cross-check of the header height for ics23.
        #[arg(long)]
        block: Option<PathBuf>,
        #[arg(long)]
        proof: PathBuf,
        /// CometBFT /header?height=H+1 response (ics23 AppHash source).
        #[arg(long)]
        header: Option<PathBuf>,
        /// AppHash as raw hex (alternative to --header).
        #[arg(long)]
        app_hash: Option<String>,
        /// AppHash trust boundary: --header/--app-hash roots are caller-supplied
        /// and NOT light-client-verified, so they are REFUSED by default.
        /// This dev/test opt-in admits them — and taints the verdict.
        #[arg(long, default_value_t = false)]
        allow_unverified_header: bool,
        /// mpt | ics23 (default: auto-detect from proof bytes).
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        handle: String,
        #[arg(long)]
        grantee: String,
        /// compute | reencrypt-to-self | reveal
        #[arg(long)]
        perm: String,
        /// Optionally assert the handle owner (0x…, 20 bytes).
        #[arg(long)]
        owner: Option<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Slots { handle, grantee } => {
            let h = parse_hex::<32>(&handle).context("--handle")?;
            let g = parse_hex::<20>(&grantee).context("--grantee")?;
            println!("metaSlot 0x{}", hex::encode(meta_slot(&h)));
            println!("aclSlot  0x{}", hex::encode(acl_slot(&h, &g)));
            Ok(())
        }
        Cmd::Verify {
            block,
            proof,
            header,
            app_hash,
            allow_unverified_header,
            format,
            handle,
            grantee,
            perm,
            owner,
        } => run_verify(VerifyArgs {
            block,
            proof,
            header,
            app_hash,
            allow_unverified_header,
            format,
            handle,
            grantee,
            perm,
            owner,
        }),
    }
}

struct VerifyArgs {
    block: Option<PathBuf>,
    proof: PathBuf,
    header: Option<PathBuf>,
    app_hash: Option<String>,
    allow_unverified_header: bool,
    format: Option<String>,
    handle: String,
    grantee: String,
    perm: String,
    owner: Option<String>,
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let h = parse_hex::<32>(&args.handle).context("--handle")?;
    let g = parse_hex::<20>(&args.grantee).context("--grantee")?;
    let bit = perm_bit(&args.perm)?;

    let proof = load_json(&args.proof)?;

    // The proof must be for the precompile account regardless of format.
    let addr_in_proof = proof["address"].as_str().unwrap_or_default();
    let expected_addr = format!("0x{}", hex::encode(FHE_PRECOMPILE_ADDRESS));
    if !addr_in_proof.eq_ignore_ascii_case(&expected_addr) {
        bail!("proof is for {addr_in_proof}, expected the FHE precompile {expected_addr}");
    }

    // Format: explicit flag wins, else sniff the first storage-proof node.
    let detected_ics23 = first_proof_node(&proof)?
        .map(|n| ics23_verify::looks_like_ics23(&n))
        .unwrap_or(false);
    let use_ics23 = match args.format.as_deref() {
        Some("ics23") => true,
        Some("mpt") => {
            if detected_ics23 {
                bail!(
                    "--format mpt requested, but the proof bytes are protobuf \
                     ics23 CommitmentProofs, not RLP MPT nodes. This chain \
                     (cosmos/evm) does not produce EIP-1186 proofs — use the \
                     ics23 path with a CometBFT header (ACL proof-format finding)."
                );
            }
            false
        }
        Some(other) => bail!("unknown --format {other:?} (expected mpt | ics23)"),
        None => detected_ics23,
    };

    let (meta_word, acl_word, commitment_desc) = if use_ics23 {
        verify_ics23(&args, &proof, &h, &g)?
    } else {
        verify_mpt(&args, &proof, &h, &g)?
    };

    // Semantics — identical for both formats (the ACL refusal property).
    let meta = match meta_word {
        Some(word) => decode_meta(&word),
        None => bail!(
            "handleMeta[h] proven ABSENT — handle was never registered; \
             a KMS must refuse this request"
        ),
    };
    if !meta.exists {
        bail!("handleMeta[h] present but exists flag unset — refuse");
    }
    if let Some(o) = &args.owner {
        let want = format!("0x{}", hex::encode(parse_hex::<20>(o)?));
        if !meta.owner.eq_ignore_ascii_case(&want) {
            bail!("owner mismatch: proven {} vs asserted {}", meta.owner, want);
        }
    }
    let acl_word = match acl_word {
        Some(word) => word,
        None => bail!(
            "acl[h][grantee] proven ABSENT — no grant exists; \
             a KMS must refuse this request (this is the ACL refusal property)"
        ),
    };
    if !has_perm(&acl_word, bit) {
        bail!(
            "grant word 0x{} does NOT carry permission {:?} — refuse",
            hex::encode(acl_word),
            args.perm
        );
    }

    println!(
        "ACL-PROOF-OK {}\n  handle  0x{}\n  owner   {} (ktype {})\n  grantee 0x{} perm {:?} GRANTED (word 0x…{:02x})",
        commitment_desc,
        hex::encode(h),
        meta.owner,
        meta.ktype,
        hex::encode(g),
        args.perm,
        acl_word[31],
    );
    Ok(())
}

// ---------------------------------------------------------------- ics23 path

fn verify_ics23(
    args: &VerifyArgs,
    proof: &Value,
    h: &[u8; 32],
    g: &[u8; 20],
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>, String)> {
    // Root candidate: AppHash, from --app-hash or a CometBFT header file.
    // Both are CALLER-SUPPLIED, i.e. unverified — the trust gate below decides
    // whether that is acceptable. A light-client-verified source would enter
    // here as AppHashSource::LightClientVerified (KMS service).
    let (app_hash, header_height) = match (&args.app_hash, &args.header) {
        (Some(hexstr), _) => (parse_hex::<32>(hexstr).context("--app-hash")?, None),
        (None, Some(path)) => {
            let header = load_json(path)?;
            let hdr = &header["header"];
            let hash_str = hdr["app_hash"]
                .as_str()
                .context("header JSON has no header.app_hash")?;
            let height: Option<u64> = hdr["height"].as_str().and_then(|s| s.parse().ok());
            (parse_hex::<32>(hash_str).context("header.app_hash")?, height)
        }
        (None, None) => bail!(
            "ics23 proofs detected: the trusted root is the CometBFT AppHash, \
             not the EVM stateRoot. Pass --header header.json (from \
             curl 'http://127.0.0.1:26657/header?height=H+1', where H is the \
             EVM block the proof was fetched at) or --app-hash 0x…"
        ),
    };

    // AppHash trust boundary: refuse unverified roots unless the dev flag opted in.
    let admitted = TrustPolicy {
        allow_unverified: args.allow_unverified_header,
    }
    .admit(AppHashSource::UnverifiedCallerSupplied {
        app_hash,
        height: header_height,
    })?;
    let app_hash = admitted.app_hash;

    // Optional height sanity check: header must be at EVM block height + 1.
    if let (Some(block_path), Some(hh)) = (&args.block, header_height) {
        let block = load_json(block_path)?;
        if let Some(num_hex) = block["number"].as_str() {
            let block_num = u64::from_str_radix(num_hex.trim_start_matches("0x"), 16)
                .context("block.number")?;
            if hh != block_num + 1 {
                bail!(
                    "header height {hh} does not match proof height + 1 \
                     (block.json is at {block_num}; AppHash at height N commits \
                     the state after block N−1, so fetch the header at {})",
                    block_num + 1
                );
            }
        }
    }

    let meta = expect_slot_ics23(proof, &app_hash, &meta_slot(h)).context("handleMeta[h]")?;
    let aclw = expect_slot_ics23(proof, &app_hash, &acl_slot(h, g)).context("acl[h][grantee]")?;
    let desc = format!(
        "format=ics23 appHash=0x{}{}{}",
        hex::encode(app_hash),
        header_height
            .map(|hh| format!(" header_height={hh}"))
            .unwrap_or_default(),
        admitted.taint_label(),
    );
    Ok((meta, aclw, desc))
}

fn expect_slot_ics23(
    proof: &Value,
    app_hash: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Option<[u8; 32]>> {
    let entry = find_slot_entry(proof, slot)?;
    let nodes = hex_array(&entry["proof"])?;
    match ics23_verify::verify_slot(app_hash, &FHE_PRECOMPILE_ADDRESS, slot, &nodes)? {
        SlotOutcome::Present(word) => Ok(Some(word)),
        SlotOutcome::Absent => Ok(None),
    }
}

// ------------------------------------------------------------------ mpt path

fn verify_mpt(
    args: &VerifyArgs,
    proof: &Value,
    h: &[u8; 32],
    g: &[u8; 20],
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>, String)> {
    let block_path = args
        .block
        .as_ref()
        .context("mpt verification needs --block for the stateRoot")?;
    let block = load_json(block_path)?;

    // 1) state root from the block header.
    let state_root: [u8; 32] = parse_hex(
        block["stateRoot"]
            .as_str()
            .context("block JSON has no stateRoot")?,
    )?;
    let block_number = block["number"].as_str().unwrap_or("?").to_string();

    // 2) account proof: keccak(address) under stateRoot → account RLP.
    let account_nodes = hex_array(&proof["accountProof"]).context("accountProof")?;
    let account_rlp = match verify_proof(
        &state_root,
        &keccak256(&FHE_PRECOMPILE_ADDRESS),
        &account_nodes,
    )
    .context("account proof vs stateRoot")?
    {
        ProofOutcome::Present(v) => v,
        ProofOutcome::Absent => bail!(
            "the FHE precompile account is ABSENT under stateRoot — \
             precompile account not initialized at this block"
        ),
    };

    // Account = RLP[nonce, balance, storageRoot, codeHash].
    let acct = rlp::Rlp::new(&account_rlp);
    if acct.item_count()? != 4 {
        bail!("account leaf is not a 4-item RLP list");
    }
    let storage_root_bytes = acct.at(2)?.data()?;
    let mut storage_root = [0u8; 32];
    storage_root.copy_from_slice(storage_root_bytes);

    // Cross-check against the proof's own storageHash claim.
    if let Some(claimed) = proof["storageHash"].as_str() {
        let claimed: [u8; 32] = parse_hex(claimed)?;
        if claimed != storage_root {
            bail!("storageHash in proof does not match the proven account's storageRoot");
        }
    }

    let meta = expect_slot_mpt(proof, &storage_root, &meta_slot(h)).context("handleMeta[h]")?;
    let aclw = expect_slot_mpt(proof, &storage_root, &acl_slot(h, g)).context("acl[h][grantee]")?;
    let desc = format!(
        "format=mpt block={} stateRoot=0x{}",
        block_number,
        hex::encode(state_root)
    );
    Ok((meta, aclw, desc))
}

/// Find the storageProof entry for `slot`, verify it against `storage_root`,
/// and return the padded 32-byte word (None = proven absent).
fn expect_slot_mpt(
    proof: &Value,
    storage_root: &[u8; 32],
    slot: &[u8; 32],
) -> Result<Option<[u8; 32]>> {
    let entry = find_slot_entry(proof, slot)?;
    let nodes = hex_array(&entry["proof"])?;
    match verify_proof(storage_root, &keccak256(slot), &nodes)? {
        ProofOutcome::Present(rlp_value) => {
            // Storage leaf values are RLP(trimmed big-endian word).
            let inner = rlp::Rlp::new(&rlp_value);
            let bytes = if inner.is_data() {
                inner.data()?.to_vec()
            } else {
                rlp_value.clone()
            };
            Ok(Some(storage_word(&bytes)?))
        }
        ProofOutcome::Absent => Ok(None),
    }
}

// -------------------------------------------------------------------- shared

fn find_slot_entry<'a>(proof: &'a Value, slot: &[u8; 32]) -> Result<&'a Value> {
    let entries = proof["storageProof"]
        .as_array()
        .context("proof JSON has no storageProof array")?;
    entries
        .iter()
        .find(|e| {
            e["key"]
                .as_str()
                .and_then(|k| parse_hex_padded::<32>(k).ok())
                .map(|k| k == *slot)
                .unwrap_or(false)
        })
        .with_context(|| format!("no storageProof entry for slot 0x{}", hex::encode(slot)))
}

/// First raw node of the first storage proof (format sniffing).
fn first_proof_node(proof: &Value) -> Result<Option<Vec<u8>>> {
    let node = proof["storageProof"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["proof"].as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.as_str())
        .map(|s| hex::decode(s.trim_start_matches("0x")))
        .transpose()?;
    Ok(node)
}

fn load_json(path: &Path) -> Result<Value> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let v: Value = serde_json::from_str(&raw)?;
    // Accept either a raw result object or a full JSON-RPC envelope.
    Ok(if v.get("result").is_some() {
        v["result"].clone()
    } else {
        v
    })
}

fn hex_array(v: &Value) -> Result<Vec<Vec<u8>>> {
    v.as_array()
        .context("expected a JSON array of hex strings")?
        .iter()
        .map(|s| {
            let s = s.as_str().context("expected hex string")?;
            Ok(hex::decode(s.trim_start_matches("0x"))?)
        })
        .collect()
}

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != N {
        bail!("expected {N} bytes, got {}", bytes.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Like parse_hex but tolerates missing leading zeroes (eth_getProof echoes
/// keys in unpadded form on some nodes).
fn parse_hex_padded<const N: usize>(s: &str) -> Result<[u8; N]> {
    let s = s.trim_start_matches("0x");
    let padded = format!("{:0>width$}", s, width = N * 2);
    parse_hex(&padded)
}
