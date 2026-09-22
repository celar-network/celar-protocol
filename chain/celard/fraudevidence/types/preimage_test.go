//go:build test

package types

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type attVector struct {
	Input struct {
		ChainID      uint64 `json:"chain_id"`
		Height       uint64 `json:"height"`
		TxIndex      uint32 `json:"tx_index"`
		LogIndex     uint32 `json:"log_index"`
		ResultHandle string `json:"result_handle"`
		CtDigest     string `json:"ct_digest"`
	} `json:"input"`
	Go     string `json:"preimage_keccak_go"`
	Copro  string `json:"preimage_keccak_coprocessor"`
}

func hash32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q: %v", s, err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func TestAttestationPreimageMatchesTheSharedVector(t *testing.T) {
	raw, err := os.ReadFile("../../../../testdata/attestation/vector.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v attVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	got := hex.EncodeToString(func() []byte {
		p := AttestationPreimage(v.Input.ChainID, v.Input.Height,
			v.Input.TxIndex, v.Input.LogIndex,
			hash32(t, v.Input.ResultHandle), hash32(t, v.Input.CtDigest))
		return p[:]
	}())
	if v.Go == "" {
		t.Fatalf("vector has no recorded value; this run computed %s", got)
	}
	if got != v.Go {
		t.Fatalf("preimage drifted:\n got %s\n want %s", got, v.Go)
	}
	if v.Copro != "" && v.Copro != got {
		t.Fatalf("THE TWO IMPLEMENTATIONS DISAGREE:\n  go   %s\n  copro %s", got, v.Copro)
	}
}

// Swapping the transaction and log indices must change the preimage. A
// packing that merged or reordered them would convict the wrong computation,
// and would do it silently.
func TestStreamPositionDoesNotAlias(t *testing.T) {
	h := hash32(t, "1111111111111111111111111111111111111111111111111111111111111111")
	d := hash32(t, "2222222222222222222222222222222222222222222222222222222222222222")
	a := AttestationPreimage(1, 9, 7, 3, h, d)
	b := AttestationPreimage(1, 9, 3, 7, h, d)
	if a == b {
		t.Fatal("tx index and log index alias: swapping them left the preimage unchanged")
	}
}
