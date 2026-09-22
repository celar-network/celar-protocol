//go:build test

package types

import (
	"encoding/json"
	"os"
	"testing"
)

const vectorPath = "../../../../testdata/endorsement/vector.json"

type vector struct {
	Input struct {
		CommitteeParties uint64  `json:"committee_parties"`
		SessionID        uint64  `json:"session_id"`
		Params           string  `json:"params"`
		Tag              string  `json:"tag"`
		PkGSHA256        string  `json:"pk_g_sha256"`
		RosterSHA256     *string `json:"roster_sha256"`
	} `json:"input"`
	DigestGo  string `json:"digest_go"`
	DigestKMS string `json:"digest_kms"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

// The vector's digest is the recorded agreement between two implementations.
// This test is what makes the Go side answerable for it.
func TestEndorsementDigestMatchesTheSharedVector(t *testing.T) {
	v := loadVector(t)
	got, err := EndorsementDigest(
		v.Input.CommitteeParties, v.Input.SessionID,
		v.Input.Params, v.Input.Tag, v.Input.PkGSHA256, v.Input.RosterSHA256)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if v.DigestGo == "" {
		t.Fatalf("vector has no recorded digest; this run computed %s", got)
	}
	if got != v.DigestGo {
		t.Fatalf("digest drifted from the vector:\n got %s\n want %s", got, v.DigestGo)
	}
	if v.DigestKMS != "" && v.DigestKMS != got {
		t.Fatalf("THE TWO IMPLEMENTATIONS DISAGREE:\n  go  %s\n  kms %s", got, v.DigestKMS)
	}
}

// An absent roster must serialise as null and keep the array at seven
// elements. Dropping the element instead would shift every later field and
// produce a digest that is wrong only for dev-mode rosterless ceremonies —
// the configuration least likely to be tested and most likely to be running.
func TestAbsentRosterIsNullNotOmitted(t *testing.T) {
	with, err := EndorsementDigest(4, 1, "p", "t", "pk", strPtr(""))
	if err != nil {
		t.Fatal(err)
	}
	without, err := EndorsementDigest(4, 1, "p", "t", "pk", nil)
	if err != nil {
		t.Fatal(err)
	}
	if with == without {
		t.Fatalf("an empty roster string and an absent roster produced the same digest")
	}
}

func strPtr(s string) *string { return &s }
