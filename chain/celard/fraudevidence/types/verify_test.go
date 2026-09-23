//go:build test

package types

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const testChainID = 23529

type attVectorFile struct {
	Input struct {
		ChainID      uint64 `json:"chain_id"`
		Height       uint64 `json:"height"`
		TxIndex      uint32 `json:"tx_index"`
		LogIndex     uint32 `json:"log_index"`
		ResultHandle string `json:"result_handle"`
		CtDigest     string `json:"ct_digest"`
	} `json:"input"`
	Signing struct {
		CoprocessorID string `json:"coprocessor_id"`
		Signature     string `json:"signature"`
	} `json:"signing"`
}

func loadAttVector(t *testing.T) attVectorFile {
	t.Helper()
	raw, err := os.ReadFile("../../../../testdata/attestation/vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v attVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

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

// The cross-language check that matters: a signature produced by the OTHER
// implementation must verify here.
//
// The preimage vector proves the two sides hash the same bytes. It says
// nothing about the signature's encoding, the recovery id's convention, or
// low-s - three things each side implements separately, where a disagreement
// rejects honest work and looks like a fault in whichever component is
// examined second.
func TestSignatureFromTheProducingSideVerifies(t *testing.T) {
	v := loadAttVector(t)
	if v.Signing.Signature == "" {
		t.Skip("producing side has not recorded a signature yet")
	}
	sig, err := hex.DecodeString(v.Signing.Signature)
	if err != nil {
		t.Fatalf("signature is not hex: %v", err)
	}
	id, err := hex.DecodeString(v.Signing.CoprocessorID)
	if err != nil {
		t.Fatalf("coprocessor id is not hex: %v", err)
	}

	a := &Attestation{
		Height: v.Input.Height, TxIndex: v.Input.TxIndex, LogIndex: v.Input.LogIndex,
		ResultHandle: mustHex(t, v.Input.ResultHandle),
		CtDigest:     mustHex(t, v.Input.CtDigest),
		EnvVersion:   EnvDigestAndSignature,
		CoprocessorId: id,
		Signature:     sig,
	}
	if err := VerifyAttestation(v.Input.ChainID, a); err != nil {
		t.Fatalf("a signature from the producing side was rejected here: %v", err)
	}

	// And the verifier must not accept a tampered one, or the test above
	// would pass for a verifier that accepts everything.
	a.Signature = append([]byte(nil), sig...)
	a.Signature[0] ^= 0x01
	if err := VerifyAttestation(v.Input.ChainID, a); err == nil {
		t.Fatal("a corrupted signature was accepted")
	}
}
