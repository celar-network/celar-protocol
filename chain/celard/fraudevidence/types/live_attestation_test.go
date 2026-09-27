package types

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The cross-language check. Rust signs, Go verifies, and the vector between
// them came out of a chain rather than out of either test suite.
//
// # Why this exists when both sides already have tests
//
// The preimage is built twice — once in Rust to sign, once here to recover —
// from a domain string, a chain id, a stream position, a handle and a digest.
// The low-s rule is implemented twice. Until now both implementations were
// checked against hand-written vectors, which means each side was tested
// against a document rather than against the other side. A document agrees
// with whoever wrote it.
//
// Regenerate with: cargo run --example live  (in fhe/coprocessor, devnet up).
const liveVectorPath = "../../../../testdata/attestation/live-devnet.json"

type liveVector struct {
	ChainID      uint64 `json:"chain_id"`
	Attestations []struct {
		Height        uint64 `json:"height"`
		TxIndex       uint32 `json:"tx_index"`
		LogIndex      uint32 `json:"log_index"`
		ResultHandle  string `json:"result_handle"`
		CtDigest      string `json:"ct_digest"`
		EnvVersion    uint32 `json:"env_version"`
		CoprocessorID string `json:"coprocessor_id"`
		Signature     string `json:"signature"`
	} `json:"attestations"`
}

func loadLiveVector(t *testing.T) liveVector {
	t.Helper()
	raw, err := os.ReadFile(liveVectorPath)
	if err != nil {
		t.Skipf("no live vector at %s; regenerate with the coprocessor's live "+
			"example against a running devnet: %v", liveVectorPath, err)
	}
	var v liveVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Attestations) == 0 {
		t.Fatal("vector carries no attestations, so this test would pass vacuously")
	}
	if v.ChainID == 0 {
		t.Fatal("vector carries no chain id; the preimage binds it, so a zero " +
			"here would silently verify against the wrong chain")
	}
	return v
}

func unhex(t *testing.T, s string, want int) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	if len(b) != want {
		t.Fatalf("decoded %d bytes, want %d, from %q", len(b), want, s)
	}
	return b
}

func (v liveVector) attestation(t *testing.T, i int) *Attestation {
	t.Helper()
	a := v.Attestations[i]
	return &Attestation{
		Height:        a.Height,
		TxIndex:       a.TxIndex,
		LogIndex:      a.LogIndex,
		ResultHandle:  unhex(t, a.ResultHandle, 32),
		CtDigest:      unhex(t, a.CtDigest, 32),
		EnvVersion:    a.EnvVersion,
		CoprocessorId: unhex(t, a.CoprocessorID, 20),
		Signature:     unhex(t, a.Signature, 65),
	}
}

func TestLiveAttestationsFromTheCoprocessorVerify(t *testing.T) {
	v := loadLiveVector(t)
	for i := range v.Attestations {
		if err := VerifyAttestation(v.ChainID, v.attestation(t, i)); err != nil {
			t.Fatalf("attestation %d (height %d, log %d) does not verify: %v",
				i, v.Attestations[i].Height, v.Attestations[i].LogIndex, err)
		}
	}
	t.Logf("%d live attestations verified against chain id %d",
		len(v.Attestations), v.ChainID)
}

// The control. Every field below is in the preimage, so changing any one of
// them must break recovery. Without this, a verifier that ignored the preimage
// entirely would pass the test above.
func TestLiveAttestationsFailWhenAnyBoundFieldMoves(t *testing.T) {
	v := loadLiveVector(t)

	for _, tc := range []struct {
		name   string
		break_ func(a *Attestation)
	}{
		{"result handle", func(a *Attestation) { a.ResultHandle[0] ^= 1 }},
		{"ciphertext digest", func(a *Attestation) { a.CtDigest[31] ^= 1 }},
		{"height", func(a *Attestation) { a.Height++ }},
		{"tx index", func(a *Attestation) { a.TxIndex++ }},
		{"log index", func(a *Attestation) { a.LogIndex++ }},
		{"signature", func(a *Attestation) { a.Signature[10] ^= 1 }},
	} {
		a := v.attestation(t, 0)
		tc.break_(a)
		if err := VerifyAttestation(v.ChainID, a); err == nil {
			t.Fatalf("%s moved and the attestation still verified: the field is "+
				"not bound by the preimage either side signs", tc.name)
		}
	}

	// The chain id is bound too, and it is the one an operator can get wrong
	// without any file being corrupt.
	a := v.attestation(t, 0)
	if err := VerifyAttestation(v.ChainID+1, a); err == nil {
		t.Fatal("verified under the wrong chain id: an attestation from another " +
			"network would be admissible here")
	}
}
