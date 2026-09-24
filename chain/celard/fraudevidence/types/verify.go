package types

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// EnvDigestAndSignature is the only commitment scheme this code can verify:
// a ciphertext digest plus a bonded signature over it.
const EnvDigestAndSignature = 1

// VerifyAttestation checks that an attestation was signed by the coprocessor
// it names, over the fields it carries.
//
// The chain recovers the signer rather than looking it up. There is no
// coprocessor registry and deliberately so: the identity IS the key, derived
// from it as the last twenty bytes of the hash of the uncompressed public key,
// which is the same identity a fraud verdict debits. Two identities - one to
// sign with, one to be slashed at - would need a mapping between them, and
// that mapping is the registry under another name.
//
// The cost of that choice, stated here because it is easy to meet by surprise:
// a key IS an identity, so rotating a key is becoming a new coprocessor and
// re-bonding. There is no rotation in place.
func VerifyAttestation(chainID uint64, a *Attestation) error {
	if a == nil {
		return fmt.Errorf("attestation: nil")
	}

	// An unknown scheme is refused rather than ignored. The version field
	// exists so a later scheme can arrive carrying a validity proof; code
	// that shrugged at a version it cannot check would record an
	// unverified claim under a version number implying it had been.
	if a.EnvVersion != EnvDigestAndSignature {
		return fmt.Errorf(
			"attestation: commitment scheme %d cannot be verified by this version",
			a.EnvVersion)
	}

	if len(a.ResultHandle) != 32 {
		return fmt.Errorf("attestation: result handle is %d bytes, want 32",
			len(a.ResultHandle))
	}
	if len(a.CtDigest) != 32 {
		return fmt.Errorf("attestation: ciphertext digest is %d bytes, want 32",
			len(a.CtDigest))
	}
	if len(a.CoprocessorId) != 20 {
		return fmt.Errorf("attestation: coprocessor id is %d bytes, want 20",
			len(a.CoprocessorId))
	}
	if len(a.Signature) != 65 {
		return fmt.Errorf("attestation: signature is %d bytes, want 65 (r||s||v)",
			len(a.Signature))
	}

	r := new(big.Int).SetBytes(a.Signature[:32])
	s := new(big.Int).SetBytes(a.Signature[32:64])
	v := a.Signature[64]
	if v > 1 {
		return fmt.Errorf(
			"attestation: recovery id is %d, want 0 or 1", v)
	}

	// Low-s is REQUIRED and NOT normalised: a high-s signature is rejected,
	// not repaired. Both encodings verify under the curve, so normalising
	// would let one operation have two valid attestations with different
	// bytes - and the store refuses conflicting claims at one position by
	// comparing what it was given. A second valid encoding is therefore not
	// a cosmetic difference; it is a second admissible record of one fact.
	if !crypto.ValidateSignatureValues(v, r, s, true) {
		return fmt.Errorf(
			"attestation: signature values rejected (high-s is refused, not normalised)")
	}

	preimage := AttestationPreimage(
		chainID, a.Height, a.TxIndex, a.LogIndex,
		[32]byte(a.ResultHandle), [32]byte(a.CtDigest))

	pub, err := crypto.SigToPub(preimage[:], a.Signature)
	if err != nil {
		return fmt.Errorf("attestation: signature does not recover a key: %w", err)
	}
	signer := crypto.PubkeyToAddress(*pub)

	if !bytes.Equal(signer.Bytes(), a.CoprocessorId) {
		return fmt.Errorf(
			"attestation: signed by %s but claims to be from %s",
			signer, common.BytesToAddress(a.CoprocessorId))
	}
	return nil
}
