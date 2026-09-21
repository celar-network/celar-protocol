package types

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/crypto"
)

// AttestDomain separates the attestation preimage from every other preimage
// the project hashes.
const AttestDomain = "celar.copro.attest.v1"

// chainIDBytes and streamRefBytes exist as named functions for the same
// reason their counterparts do on the producing side: the protocol fixes
// every integer field in every preimage as fixed-width big-endian, and the
// rule is wider than this one signature.
//
// The re-randomization seed hashes the same two fields, and a mismatch there
// does NOT surface as a rejected attestation — it yields a different seed, a
// different ciphertext and therefore a different attested digest, which the
// determinism obligations make consensus-critical. Anything deriving a
// preimage from these fields must call these rather than pack them again.
func chainIDBytes(chainID uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, chainID)
	return out
}

// Height, then transaction index, then log index, big-endian, packed — the
// order the canonical stream ordering already sorts by.
//
// The widths are load-bearing rather than incidental: fixed widths make
// position aliasing impossible, so a transaction index and a log index cannot
// be swapped into the same bytes. A loose packing would surface that as an
// inexplicable fraud verdict rather than a decode error.
func streamRefBytes(height uint64, txIndex, logIndex uint32) []byte {
	out := make([]byte, 16)
	binary.BigEndian.PutUint64(out[:8], height)
	binary.BigEndian.PutUint32(out[8:12], txIndex)
	binary.BigEndian.PutUint32(out[12:], logIndex)
	return out
}

// AttestationPreimage rebuilds the 32 bytes a coprocessor signs.
//
// The chain recomputes this from the submitted fields. It must never accept a
// submitted digest beside the fields it claims to cover: nothing would force
// the two to agree, and a signature valid over a digest that contradicts the
// fields is a conviction path resting on attacker-supplied data.
func AttestationPreimage(
	chainID uint64,
	height uint64,
	txIndex uint32,
	logIndex uint32,
	resultHandle [32]byte,
	ctDigest [32]byte,
) [32]byte {
	var preimage []byte
	preimage = append(preimage, []byte(AttestDomain)...)
	preimage = append(preimage, chainIDBytes(chainID)...)
	preimage = append(preimage, streamRefBytes(height, txIndex, logIndex)...)
	preimage = append(preimage, resultHandle[:]...)
	preimage = append(preimage, ctDigest[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}
