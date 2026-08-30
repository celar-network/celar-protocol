package types

import (
	"encoding/binary"
	"fmt"
)

const (
	// ModuleName is also the store key, and the store name is part of the
	// proof path the KMS verifier checks — it cannot change without
	// changing that verifier.
	ModuleName = "epochcommit"
	StoreKey   = ModuleName
)

var (
	// EntryPrefix namespaces per-(epoch, seat) commitments.
	EntryPrefix = []byte{0x01}
	// OldestRetainedEpochKey and LatestEpochKey are NEVER pruned. They are
	// what make absence decidable: below the first is time-barred, above
	// the second never existed, and in between is an anomaly. A bare
	// missing key cannot tell those three apart, and conflating them lets
	// expired evidence read as forged or forged evidence read as expired.
	OldestRetainedEpochKey = []byte{0x02}
	LatestEpochKey         = []byte{0x03}
)

// ErrInvalidSeatRole is returned for seat role 0. Roles are one-based by
// interface agreement; a lookup on 0 that merely missed would be
// indistinguishable from a pruned epoch, collapsing two verdicts into one.
var ErrInvalidSeatRole = fmt.Errorf("seat role is one-based; 0 is invalid")

// EntryKey is prefix ‖ epoch ‖ seat_role, both big-endian so that byte
// order matches numeric order — the pruning sweep walks epochs in order and
// relies on that.
func EntryKey(epoch uint64, seatRole uint32) ([]byte, error) {
	if seatRole == 0 {
		return nil, ErrInvalidSeatRole
	}
	k := make([]byte, 0, len(EntryPrefix)+8+4)
	k = append(k, EntryPrefix...)
	k = binary.BigEndian.AppendUint64(k, epoch)
	k = binary.BigEndian.AppendUint32(k, seatRole)
	return k, nil
}

// EpochPrefix is every seat within one epoch, for the pruning sweep.
func EpochPrefix(epoch uint64) []byte {
	k := make([]byte, 0, len(EntryPrefix)+8)
	k = append(k, EntryPrefix...)
	return binary.BigEndian.AppendUint64(k, epoch)
}
