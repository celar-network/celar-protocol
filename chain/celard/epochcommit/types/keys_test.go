package types

import (
	"bytes"
	"errors"
	"testing"
)

func TestSeatRoleZeroIsRejected(t *testing.T) {
	if _, err := EntryKey(1, 0); !errors.Is(err, ErrInvalidSeatRole) {
		t.Fatalf("expected rejection of seat role 0, got %v", err)
	}
	if _, err := EntryKey(1, 1); err != nil {
		t.Fatalf("one-based first role rejected: %v", err)
	}
}

// The pruning sweep walks epochs in order and deletes below a horizon, so
// byte order has to match numeric order. Little-endian would pass a
// round-trip test and silently break the sweep.
func TestKeyOrderMatchesNumericOrder(t *testing.T) {
	prev, _ := EntryKey(0, 1)
	for _, e := range []uint64{1, 255, 256, 1 << 20, 1 << 40} {
		cur, _ := EntryKey(e, 1)
		if bytes.Compare(prev, cur) >= 0 {
			t.Fatalf("epoch %d does not sort after its predecessor", e)
		}
		prev = cur
	}
	// and within one epoch, seats sort by role
	a, _ := EntryKey(7, 1)
	b, _ := EntryKey(7, 2)
	if bytes.Compare(a, b) >= 0 {
		t.Fatal("seat roles do not sort within an epoch")
	}
}

func TestEpochPrefixCoversItsSeats(t *testing.T) {
	p := EpochPrefix(7)
	for _, role := range []uint32{1, 2, 100} {
		k, _ := EntryKey(7, role)
		if !bytes.HasPrefix(k, p) {
			t.Fatalf("role %d not under its epoch prefix", role)
		}
	}
	if other, _ := EntryKey(8, 1); bytes.HasPrefix(other, p) {
		t.Fatal("a different epoch fell under this epoch's prefix")
	}
}
