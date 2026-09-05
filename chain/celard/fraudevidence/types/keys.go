package types

import (
	"encoding/binary"
	"fmt"
)

const (
	// ModuleName is also the store key. Unlike the commitment archive's,
	// this store name is not on any proof path an external verifier reads
	// today — but the archive's became load-bearing the moment a verifier
	// proved through it, so it is treated as fixed from the start rather
	// than as a name we could still change.
	ModuleName = "fraudevidence"
	StoreKey   = ModuleName
)

var (
	// VerdictPrefix namespaces recorded convictions by (epoch, seat).
	//
	// Keyed the same way the archive keys commitments, deliberately: a
	// conviction names a seat within an epoch, and a second native module
	// storing the same pair differently would be two conventions for one
	// kind of thing.
	VerdictPrefix = []byte{0x01}

	// AttestationPrefix namespaces coprocessor result attestations by
	// stream position.
	//
	// Same module, different message: the submission surface was decided
	// once for both, because answering it twice produces two mechanisms
	// that do not compose.
	AttestationPrefix = []byte{0x02}
)

// ErrInvalidSeatRole mirrors the archive's rule rather than restating it
// loosely: roles are one-based, and 0 is malformed evidence rather than a
// seat. A lookup on 0 that merely missed would be indistinguishable from a
// verdict that was never recorded.
var ErrInvalidSeatRole = fmt.Errorf("seat role is one-based; 0 is invalid")

// VerdictKey is prefix ‖ epoch ‖ seat_role, both big-endian so byte order
// matches numeric order — the same reason the archive does it, and it lets
// a sweep walk an epoch's convictions in order.
func VerdictKey(epoch uint64, seatRole uint32) ([]byte, error) {
	if seatRole == 0 {
		return nil, ErrInvalidSeatRole
	}
	k := make([]byte, 0, len(VerdictPrefix)+8+4)
	k = append(k, VerdictPrefix...)
	k = binary.BigEndian.AppendUint64(k, epoch)
	k = binary.BigEndian.AppendUint32(k, seatRole)
	return k, nil
}

// VerdictEpochPrefix is every conviction within one epoch.
func VerdictEpochPrefix(epoch uint64) []byte {
	k := make([]byte, 0, len(VerdictPrefix)+8)
	k = append(k, VerdictPrefix...)
	return binary.BigEndian.AppendUint64(k, epoch)
}

// AttestationKey is prefix ‖ height ‖ txIndex ‖ logIndex — the canonical
// stream order, packed exactly as the protocol pins it for preimages.
//
// Using the same widths here is not decoration: an attestation is looked up
// by the position it attests to, and a second packing of the same triple
// would be the drift the pinned encoding exists to prevent.
func AttestationKey(height uint64, txIndex, logIndex uint32) []byte {
	k := make([]byte, 0, len(AttestationPrefix)+16)
	k = append(k, AttestationPrefix...)
	k = binary.BigEndian.AppendUint64(k, height)
	k = binary.BigEndian.AppendUint32(k, txIndex)
	return binary.BigEndian.AppendUint32(k, logIndex)
}

// ErrConflictingVerdict is returned when a second conviction names the same
// seat and epoch on different evidence. Not silently overwritten: the stored
// record is what a slash was applied against, and replacing it would erase
// the basis of an action already taken.
var ErrConflictingVerdict = fmt.Errorf("a different verdict is already recorded for this seat and epoch")

// ErrNoSuchVerdict is returned when punishment is claimed for a conviction
// that was never recorded.
var ErrNoSuchVerdict = fmt.Errorf("no verdict recorded for this seat and epoch")

// ErrConflictingAttestation is returned when a second attestation names the
// same stream position with a different result. Not overwritten: a
// re-execution dispute is settled against what was attested, and replacing
// the record would change what a challenge compares against.
var ErrConflictingAttestation = fmt.Errorf("a different attestation is already recorded for this stream position")
