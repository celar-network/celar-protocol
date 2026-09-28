package fhe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Input-proof verification seam.
//
// An admitted input must carry a proof (π_in) whose PUBLIC INPUTS bind the
// submission to its context, so that a proof copied from the mempool fails
// verification anywhere but its original context:
//
//	(chain_id, target contract, submitter, tx-scope, expiry height)
//
// The submitter is the transaction origin — the same principal the admission
// handle derivation binds — so a replayed proof cannot be re-admitted by a
// different party, and a self-replay re-derives a handle the submitter
// already owns. The expiry bounds how long a copied proof stays live at all.
//
// The proof argument of verifyInput carries these public inputs in a
// fixed-layout envelope ahead of the proof body (see parseInputProofEnvelope).
// Carrying them inside the existing `bytes proof` argument means the frozen
// precompile signature does not change.
//
// What is enforced HERE, chain-side, today: envelope well-formedness and the
// context checks — chain id, submitter = origin, target = the admitting
// caller, and the expiry window. These are chain facts the precompile can
// check without any cryptography.
//
// What is NOT enforced today: the proof body itself. The verifier behind
// InputProofVerifier is a development stub pending the real proof-system
// integration, and UNTIL THAT LANDS, INPUT ADMISSION REMAINS UNAUTHENTICATED:
// nothing here stops a party who re-encodes a copied ciphertext under their
// own context from admitting it. The context checks bound replay of a proof;
// only verification whose witness the copier lacks closes the disclosure
// path. Do not describe this seam as a fix for that.

// InputProofPublicInputs is the settled public-input tuple of π_in, as
// carried in the proof envelope and asserted against chain context.
type InputProofPublicInputs struct {
	// ChainID the proof was generated for.
	ChainID uint64
	// TargetContract the input is admitted to (the precompile's caller).
	TargetContract common.Address
	// Submitter is the transaction origin admitting the input.
	Submitter common.Address
	// TxScope is the relation's transaction-scope binding. Opaque to the
	// chain: the verifier checks it inside the proof; nothing chain-side
	// re-derives it.
	TxScope [32]byte
	// ExpiryHeight is the last block height (inclusive) at which this
	// proof may be admitted.
	ExpiryHeight uint64
}

// InputProofVerifier verifies an input proof against its public inputs.
// The production implementation is the proof-system verifier; the seam
// exists so integrating it changes one constructor, not the precompile.
type InputProofVerifier interface {
	VerifyInputProof(pub InputProofPublicInputs, proofBody []byte) error
}

// Envelope layout (fixed-width, big-endian), followed by the proof body:
//
//	version(1) ‖ chainId(8) ‖ target(20) ‖ submitter(20) ‖ txScope(32) ‖ expiry(8)
const (
	inputProofEnvelopeVersion = 0x01
	inputProofEnvelopeLen     = 1 + 8 + 20 + 20 + 32 + 8
)

// MaxExpiryWindowBlocks caps how far ahead a proof's expiry may sit at
// admission. Without a cap the expiry term is void — a submitter would set
// it astronomically. The cap targets roughly thirty minutes of wall clock:
// enormously above submission-to-inclusion latency (so an honest submitter
// never regenerates a proof because of it) and small enough that a copied
// proof is dead within the hour even under a hypothesised binding weakness.
//
// PINNED AGAINST MEASUREMENT (2026-09-28, single-validator devnet):
// block time 5.153s averaged over 200-block window; submission-to-inclusion
// 1 block in 30/30 sends (the idle floor — the cap is sized to the wall-clock
// target, not to congestion, and carries ~100x headroom over inclusion).
// 1800s / 5.153s per block ≈ 349 → 350. If the deployed chain's block time
// changes materially, re-derive from the same basis: ~30 minutes of wall
// clock, expressed in blocks. A submitter may always choose a shorter expiry.
const MaxExpiryWindowBlocks uint64 = 350

// parseInputProofEnvelope splits the verifyInput proof argument into the
// public-input tuple and the proof body. Malformed envelopes error — an
// admission the chain cannot attribute a context to is refused, never
// guessed at.
func parseInputProofEnvelope(bz []byte) (InputProofPublicInputs, []byte, error) {
	var pub InputProofPublicInputs
	if len(bz) < inputProofEnvelopeLen {
		return pub, nil, fmt.Errorf(
			"input proof too short for its public-input envelope: %d bytes, need %d",
			len(bz), inputProofEnvelopeLen)
	}
	if bz[0] != inputProofEnvelopeVersion {
		return pub, nil, fmt.Errorf(
			"unknown input-proof envelope version %#x (expected %#x)",
			bz[0], inputProofEnvelopeVersion)
	}
	off := 1
	pub.ChainID = binary.BigEndian.Uint64(bz[off : off+8])
	off += 8
	pub.TargetContract = common.BytesToAddress(bz[off : off+20])
	off += 20
	pub.Submitter = common.BytesToAddress(bz[off : off+20])
	off += 20
	copy(pub.TxScope[:], bz[off:off+32])
	off += 32
	pub.ExpiryHeight = binary.BigEndian.Uint64(bz[off : off+8])
	off += 8
	return pub, bz[off:], nil
}

// checkAdmissionBinding asserts the public inputs against the chain context
// of the admitting call. Everything here is a chain fact: no cryptography,
// no trust in the submitter's encoding beyond refusing it when it disagrees
// with what the chain observes.
func checkAdmissionBinding(
	pub InputProofPublicInputs,
	chainID *big.Int,
	origin common.Address,
	caller common.Address,
	height uint64,
) error {
	if chainID == nil || !chainID.IsUint64() || pub.ChainID != chainID.Uint64() {
		return fmt.Errorf(
			"input proof bound to chain id %d, this chain is %s",
			pub.ChainID, chainID)
	}
	if pub.Submitter != origin {
		return fmt.Errorf(
			"input proof bound to submitter %s, transaction origin is %s",
			pub.Submitter.Hex(), origin.Hex())
	}
	if pub.TargetContract != caller {
		return fmt.Errorf(
			"input proof bound to target %s, admitting caller is %s",
			pub.TargetContract.Hex(), caller.Hex())
	}
	if height > pub.ExpiryHeight {
		return fmt.Errorf(
			"input proof expired: expiry height %d, current height %d",
			pub.ExpiryHeight, height)
	}
	if pub.ExpiryHeight-height > MaxExpiryWindowBlocks {
		return fmt.Errorf(
			"input proof expiry too far ahead: height %d at current %d exceeds the %d-block window",
			pub.ExpiryHeight, height, MaxExpiryWindowBlocks)
	}
	return nil
}

// stubInputProofVerifier is the DEVELOPMENT verifier: it checks only that a
// proof body is present. It authenticates nothing — see the package note
// above for exactly what that means and does not mean.
type stubInputProofVerifier struct{}

func (stubInputProofVerifier) VerifyInputProof(
	_ InputProofPublicInputs, proofBody []byte,
) error {
	if len(proofBody) == 0 {
		return errors.New("empty proof body rejected")
	}
	return nil
}
