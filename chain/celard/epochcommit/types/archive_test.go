package types

import (
	"encoding/hex"
	"testing"
)

// The field numbers are the canonical encoding: an entry is hashed in its
// proto encoding under them, and the KMS-side reader declares the same four
// in the same order. Today that agreement is held by comments on both sides.
//
// This fixture makes it hold by evidence. If a field is renumbered,
// reordered, retyped, or inserted, the bytes move and this fails — which is
// the point, because the alternative failure is silent: evidence that no
// longer verifies against a chain that thinks it is behaving correctly.
func TestWireEncodingIsPinned(t *testing.T) {
	e := ArchivedSeatCommitment{
		CommitmentSha256: "aa",
		RosterSha256:     "bb",
		KeyedHeight:      1,
		PkGSha256:        "cc",
	}
	got, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// field 1 (0x0a) "aa" | field 2 (0x12) "bb" | field 3 (0x18) 1 |
	// field 4 (0x22) "cc"
	const want = "0a02616112026262180122026363"
	if hex.EncodeToString(got) != want {
		t.Fatalf("wire bytes moved:\n got  %s\n want %s",
			hex.EncodeToString(got), want)
	}
}

// A zero seat index is invalid by interface agreement, and absence of an
// entry must stay distinguishable from a pruned epoch. Nothing in the
// generated type enforces that; the store must, and this records why.
func TestEmptyEntryRoundTrips(t *testing.T) {
	var e ArchivedSeatCommitment
	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("an empty entry should encode to zero bytes, got %d", len(b))
	}
	var back ArchivedSeatCommitment
	if err := back.Unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != e {
		t.Fatal("empty entry did not round-trip")
	}
}
