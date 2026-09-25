// Package relayer carries a coprocessor's attestations to the chain.
//
// It exists because the two jobs are different. The coprocessor decides what
// is true; submitting needs a transaction, a funded key and a nonce, and
// putting those in the component whose output the fraud game trusts would add
// a network and a key manager to the one thing that benefits from having
// neither.
//
// The submitter has no authority over what it carries. The attestation holds
// its own identity and its own signature over the pinned preimage, and the
// chain verifies both before recording anything - so who relays is not a
// trust question. That is deliberate: a coprocessor that cannot reach the
// chain should not thereby be unable to have its work recorded.
package relayer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/cosmos/evm/evmd/fraudevidence/types"
)

// handoff mirrors the file the coprocessor writes. Hex is unprefixed and
// lowercase on that side; decoding is case-insensitive here because being
// strict about the case of a hex digit would reject a file that is not
// actually ambiguous.
type handoff struct {
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

// Widths the chain will enforce anyway.
//
// Checked here too, and that is not redundant: failing on a malformed file
// costs nothing, while failing at the handler costs a built and broadcast
// transaction, its fee, and a rejection that names the chain's reason rather
// than the file's line. The duplicate check is a cheaper diagnosis, not a
// second authority.
const (
	handleLen   = 32
	digestLen   = 32
	copIDLen    = 20
	sigLen      = 65
)

// ParseHandoff reads the coprocessor's output into messages ready to submit.
//
// Every failure names the index. A file of forty attestations that reports
// only "bad length" tells the operator nothing about which one, and these are
// produced in batches.
func ParseHandoff(data []byte) ([]types.Attestation, error) {
	var h handoff
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("handoff: not the expected document: %w", err)
	}

	out := make([]types.Attestation, 0, len(h.Attestations))
	for i, a := range h.Attestations {
		handle, err := fixedHex(a.ResultHandle, handleLen, i, "result_handle")
		if err != nil {
			return nil, err
		}
		digest, err := fixedHex(a.CtDigest, digestLen, i, "ct_digest")
		if err != nil {
			return nil, err
		}
		id, err := fixedHex(a.CoprocessorID, copIDLen, i, "coprocessor_id")
		if err != nil {
			return nil, err
		}
		sig, err := fixedHex(a.Signature, sigLen, i, "signature")
		if err != nil {
			return nil, err
		}

		out = append(out, types.Attestation{
			Height:        a.Height,
			TxIndex:       a.TxIndex,
			LogIndex:      a.LogIndex,
			ResultHandle:  handle,
			CtDigest:      digest,
			EnvVersion:    a.EnvVersion,
			CoprocessorId: id,
			Signature:     sig,
		})
	}
	return out, nil
}

// fixedHex decodes and checks
//
// An absent field decodes to zero bytes rather than erroring on its own, so
// the width check is what catches it — which is why the check is unconditional
// rather than applied only to fields that are present.
func fixedHex(s string, want int, i int, field string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("attestation %d: %s is not hex: %w", i, field, err)
	}
	if len(b) != want {
		return nil, fmt.Errorf(
			"attestation %d: %s is %d bytes, want %d", i, field, len(b), want)
	}
	return b, nil
}
