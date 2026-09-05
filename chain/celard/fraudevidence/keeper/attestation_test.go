package keeper_test

import (
	"testing"

	"github.com/cosmos/evm/evmd/fraudevidence/types"
)

func attestation(digest string) types.Attestation {
	return types.Attestation{
		Height:        1000,
		TxIndex:       2,
		LogIndex:      7,
		ResultHandle:  []byte("handle"),
		CtDigest:      []byte(digest),
		EnvVersion:    1,
		CoprocessorId: []byte("copro-a"),
		Signature:     []byte("sig"),
	}
}

func TestAttestationRoundTrip(t *testing.T) {
	k, ctx := newKeeper(t)
	existed, err := k.RecordAttestation(ctx, attestation("d1"))
	if err != nil || existed {
		t.Fatalf("record: existed=%v err=%v", existed, err)
	}
	got, found, err := k.Attestation(ctx, 1000, 2, 7)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if string(got.CtDigest) != "d1" || got.EnvVersion != 1 {
		t.Fatalf("round trip lost fields: %+v", got)
	}
}

// Delivery is at-least-once and anyone may submit, so the same attestation
// arriving twice is ordinary and must not be an error.
func TestIdenticalAttestationIsANoOp(t *testing.T) {
	k, ctx := newKeeper(t)
	if _, err := k.RecordAttestation(ctx, attestation("d1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	existed, err := k.RecordAttestation(ctx, attestation("d1"))
	if err != nil || !existed {
		t.Fatalf("second: existed=%v err=%v", existed, err)
	}
}

// Two coprocessors disagreeing about one position is not an error in this
// module - it is the fraud game's subject. The first claim stays intact and
// the disagreement goes to the path that can adjudicate it; overwriting would
// destroy the evidence that they disagreed at all.
func TestConflictingAttestationDoesNotOverwriteTheFirst(t *testing.T) {
	k, ctx := newKeeper(t)
	if _, err := k.RecordAttestation(ctx, attestation("d1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := k.RecordAttestation(ctx, attestation("d2"))
	if err != types.ErrConflictingAttestation {
		t.Fatalf("expected refusal, got %v", err)
	}
	got, _, _ := k.Attestation(ctx, 1000, 2, 7)
	if string(got.CtDigest) != "d1" {
		t.Fatal("the first attestation must survive a conflicting one")
	}
}

// Positions must not alias. Height 1000/tx 2/log 7 and height 1000/tx 7/log 2
// are different operations, and a packing that confused them would let one
// attestation answer for another.
func TestPositionsDoNotAlias(t *testing.T) {
	k, ctx := newKeeper(t)
	a := attestation("d1")
	if _, err := k.RecordAttestation(ctx, a); err != nil {
		t.Fatalf("first: %v", err)
	}
	b := attestation("d2")
	b.TxIndex, b.LogIndex = 7, 2
	if _, err := k.RecordAttestation(ctx, b); err != nil {
		t.Fatalf("swapped indices must be a distinct position: %v", err)
	}
	first, _, _ := k.Attestation(ctx, 1000, 2, 7)
	second, _, _ := k.Attestation(ctx, 1000, 7, 2)
	if string(first.CtDigest) != "d1" || string(second.CtDigest) != "d2" {
		t.Fatal("the two positions collapsed into one")
	}
}
