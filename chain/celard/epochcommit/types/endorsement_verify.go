package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// RosterSchema is the only roster layout this verifier accepts.
//
// The version is load-bearing rather than decorative: the schema bump that
// introduced it also put the per-seat signing keys inside the digested bytes,
// so a roster of the same members under the previous schema is a different
// artifact by design. Accepting an unknown schema would mean verifying
// signatures against keys whose place in the committed bytes we cannot
// account for.
const RosterSchema = "celar-committee-roster/v1"

// SeatEndorsement is the generated wire type from tx.proto; this file
// deliberately does not declare its own.
//
// It carries the role alongside the signature because ed25519 offers no key
// recovery — the verifier must be told which rostered key to check against.
// That makes the role attacker-supplied, which is why nothing below trusts it
// beyond the lookup: a wrong role fails verification rather than implicating
// the seat it names.
//
// A second, hand-written copy of this struct existed here briefly and the
// compiler refused it. That refusal was correct and worth keeping in mind: two
// declarations of one wire shape is the defect this project has spent a month
// on, and here the build caught it rather than a reviewer.

// rosterMember mirrors only the two fields this check needs.
//
// Deliberately partial. The roster bytes are parsed AFTER their digest has
// been checked against the anchored value, so they are already proven; and a
// struct that mirrored every field would have to be kept in lockstep with the
// producer forever, which is the cross-language coupling that exposing the
// canonical bytes exists to avoid.
type rosterMember struct {
	Role          uint32 `json:"role"`
	SigningPubkey string `json:"signing_pubkey"`
}

type rosterDoc struct {
	Schema  string         `json:"schema"`
	Members []rosterMember `json:"members"`
}

// VerifyQuorumEndorsement checks that a reconstruction quorum of the epoch's
// rostered seats endorsed one transcript digest.
//
// The submission carries the roster's canonical bytes; this hashes THOSE bytes
// against the digest the chain already holds, and only then parses them for
// public keys. Parsing after the hash check is not a trust surface — the bytes
// are proven before anything reads them — and it is what keeps a JSON
// canonicaliser that must agree with the producer forever out of this tree.
//
// What this establishes, stated so it is not over-read: that the rostered
// quorum ENDORSES this transcript. Not that the ceremony inside it was honest.
// A colluding quorum can still sign a fabricated transcript, which is the
// trust the committee model already carries everywhere else; the limit is
// adopted deliberately and should not erode into a stronger claim.
func VerifyQuorumEndorsement(
	rosterBytes []byte,
	anchoredRosterSHA256 string,
	digestHex string,
	endorsements []SeatEndorsement,
	quorum int,
) error {
	if quorum <= 0 {
		// A quorum of zero would make every submission valid, including one
		// carrying no signatures at all. Refuse rather than treat it as
		// "no requirement": the caller has miscomputed something.
		return fmt.Errorf("endorsement: quorum must be positive, got %d", quorum)
	}

	// 1. The bytes are what the chain anchored, or nothing else matters.
	sum := sha256.Sum256(rosterBytes)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, anchoredRosterSHA256) {
		return fmt.Errorf(
			"endorsement: roster bytes do not match the anchored digest (have %s, anchored %s)",
			got, anchoredRosterSHA256,
		)
	}

	// 2. Only now parse them.
	roster, err := parseRoster(rosterBytes)
	if err != nil {
		return err
	}

	// 3. Count DISTINCT valid seat signatures.
	//
	// Distinctness is enforced on the role, and duplicate roles were already
	// refused when the roster was indexed — so one key cannot be presented
	// twice under two names, nor one role satisfied twice by repeating its
	// signature.
	seen := make(map[uint32]struct{}, len(endorsements))
	valid := 0
	message := []byte(digestHex) // the HEX STRING is the signed message, not the 32 raw bytes

	for i, e := range endorsements {
		if _, dup := seen[e.Role]; dup {
			return fmt.Errorf("endorsement %d: role %d appears twice", i, e.Role)
		}
		seen[e.Role] = struct{}{}

		pub, ok := roster[e.Role]
		if !ok {
			return fmt.Errorf("endorsement %d: role %d is not in the anchored roster", i, e.Role)
		}
		if len(e.Signature) != ed25519.SignatureSize {
			return fmt.Errorf(
				"endorsement %d: signature is %d bytes, want %d",
				i, len(e.Signature), ed25519.SignatureSize,
			)
		}
		if !ed25519.Verify(pub, message, e.Signature) {
			// Refuse the whole submission rather than skipping the bad
			// signature and counting on. A submission carrying an invalid
			// signature is malformed, and silently ignoring it would let a
			// submitter pad a short quorum with noise to see which seats the
			// chain accepts.
			return fmt.Errorf("endorsement %d: invalid signature for role %d", i, e.Role)
		}
		valid++
	}

	if valid < quorum {
		return fmt.Errorf(
			"endorsement: %d valid seat signatures, need a reconstruction quorum of %d",
			valid, quorum,
		)
	}
	return nil
}

// ReconstructionQuorum is the number of seat endorsements an epoch needs,
// derived from the anchored roster: t = 3c/4 + 1, integer division.
//
// Derived here rather than carried in the message on purpose. A quorum a
// submitter supplies is a quorum a submitter chooses, and the one number that
// decides how many signatures are enough must not be attacker-supplied. It is
// also not configurable on the producing side — "the formula IS the rule" —
// so there is nothing to read from a parameter store.
//
// The formula is mirrored from the roster type that defines it. It is NOT the
// published committee threshold: those are different quantities that have been
// conflated on this project before, and this one is only ever about how many
// endorsements authenticate an archive write.
func ReconstructionQuorum(rosterBytes []byte) (int, error) {
	roster, err := parseRoster(rosterBytes)
	if err != nil {
		return 0, err
	}
	return 3*len(roster)/4 + 1, nil
}

// parseRoster indexes role -> ed25519 public key, refusing anything ambiguous.
func parseRoster(b []byte) (map[uint32]ed25519.PublicKey, error) {
	var doc rosterDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("endorsement: roster bytes are not the expected JSON: %w", err)
	}
	if doc.Schema != RosterSchema {
		return nil, fmt.Errorf(
			"endorsement: roster schema %q is not %q", doc.Schema, RosterSchema,
		)
	}
	if len(doc.Members) == 0 {
		return nil, fmt.Errorf("endorsement: roster has no members")
	}

	out := make(map[uint32]ed25519.PublicKey, len(doc.Members))
	keys := make(map[string]uint32, len(doc.Members))

	for _, m := range doc.Members {
		if m.Role == 0 {
			// Roles are one-based by interface agreement. Zero is not a seat,
			// and admitting it here would let a lookup miss look like a seat.
			return nil, ErrInvalidSeatRole
		}
		if _, dup := out[m.Role]; dup {
			return nil, fmt.Errorf("endorsement: roster lists role %d twice", m.Role)
		}
		raw, err := hex.DecodeString(m.SigningPubkey)
		if err != nil {
			return nil, fmt.Errorf("endorsement: role %d signing key is not hex: %w", m.Role, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(
				"endorsement: role %d signing key is %d bytes, want %d",
				m.Role, len(raw), ed25519.PublicKeySize,
			)
		}
		// Two seats sharing a key would let one holder supply two of the
		// quorum's signatures. The producer refuses this at roster
		// construction; refusing it here too means the chain does not depend
		// on that having happened.
		if other, dup := keys[m.SigningPubkey]; dup {
			return nil, fmt.Errorf(
				"endorsement: roles %d and %d share a signing key", other, m.Role,
			)
		}
		keys[m.SigningPubkey] = m.Role
		out[m.Role] = ed25519.PublicKey(raw)
	}
	return out, nil
}
