//go:build test

package types

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const testChainID = 23529

func attestationSignedBy(t *testing.T, key *ecdsa.PrivateKey) *Attestation {
	t.Helper()
	a := &Attestation{
		Height: 1234567, TxIndex: 7, LogIndex: 3,
		ResultHandle: make([]byte, 32),
		CtDigest:     make([]byte, 32),
		EnvVersion:   EnvDigestAndSignature,
	}
	for i := range a.ResultHandle {
		a.ResultHandle[i] = 0x11
		a.CtDigest[i] = 0x22
	}
	p := AttestationPreimage(testChainID, a.Height, a.TxIndex, a.LogIndex,
		[32]byte(a.ResultHandle), [32]byte(a.CtDigest))
	sig, err := crypto.Sign(p[:], key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a.Signature = sig
	a.CoprocessorId = crypto.PubkeyToAddress(key.PublicKey).Bytes()
	return a
}

func TestAttestationFromItsOwnSignerVerifies(t *testing.T) {
	key, _ := crypto.GenerateKey()
	if err := VerifyAttestation(testChainID, attestationSignedBy(t, key)); err != nil {
		t.Fatalf("honest attestation rejected: %v", err)
	}
}

// The identity is recovered, not looked up, so claiming someone else's
// identity fails on the claim rather than on a registry lookup.
func TestClaimedIdentityMustBeTheSigner(t *testing.T) {
	signer, _ := crypto.GenerateKey()
	other, _ := crypto.GenerateKey()
	a := attestationSignedBy(t, signer)
	a.CoprocessorId = crypto.PubkeyToAddress(other.PublicKey).Bytes()
	if err := VerifyAttestation(testChainID, a); err == nil {
		t.Fatal("an attestation claiming another identity was accepted")
	}
}

// High-s must be REFUSED, not normalised. Both encodings recover the same
// key, so normalising would give one operation two valid attestations with
// different bytes - and the store adjudicates conflicts by comparing bytes.
func TestHighSIsRefusedRatherThanNormalised(t *testing.T) {
	key, _ := crypto.GenerateKey()
	a := attestationSignedBy(t, key)

	n := crypto.S256().Params().N
	s := new(big.Int).SetBytes(a.Signature[32:64])
	high := new(big.Int).Sub(n, s)
	copy(a.Signature[32:64], make([]byte, 32))
	high.FillBytes(a.Signature[32:64])
	a.Signature[64] ^= 1 // the matching recovery id for the flipped s

	if err := VerifyAttestation(testChainID, a); err == nil {
		t.Fatal("a high-s signature was accepted; it must be refused, not repaired")
	}
}

// Changing any signed field changes the preimage, so recovery yields a
// different address and the claim fails. The stream position is the case
// worth pinning: a swapped index would convict a different computation.
func TestTamperedStreamPositionFails(t *testing.T) {
	key, _ := crypto.GenerateKey()
	a := attestationSignedBy(t, key)
	a.TxIndex, a.LogIndex = a.LogIndex, a.TxIndex
	if err := VerifyAttestation(testChainID, a); err == nil {
		t.Fatal("swapping the stream indices left the attestation valid")
	}
}

// A chain-bound signature must not verify on another chain.
func TestSignatureDoesNotCrossChains(t *testing.T) {
	key, _ := crypto.GenerateKey()
	a := attestationSignedBy(t, key)
	if err := VerifyAttestation(testChainID+1, a); err == nil {
		t.Fatal("an attestation verified against a different chain id")
	}
}

// A scheme this code cannot check is refused, not ignored.
func TestUnknownCommitmentSchemeIsRefused(t *testing.T) {
	key, _ := crypto.GenerateKey()
	a := attestationSignedBy(t, key)
	a.EnvVersion = 2
	if err := VerifyAttestation(testChainID, a); err == nil {
		t.Fatal("an unverifiable commitment scheme was accepted")
	}
}
