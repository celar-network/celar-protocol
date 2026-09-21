package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// EndorsementDomain separates this digest from every other preimage the
// project signs. Bump only if the signed field set changes: a signature is
// over the digest, and the digest is over these fields.
const EndorsementDomain = "celar-transcript-endorsement/v1"

// EndorsementDigest recomputes the value each committee seat signs when it
// endorses a ceremony transcript.
//
// It covers the COMMON epoch fields only — committee size, session, params,
// tag, pk_G, roster — and deliberately excludes the per-seat share
// commitment, wall time, transport and the signature itself, so that a quorum
// of signatures is over one shared value.
//
// The chain recomputes this rather than accepting a submitted digest. If a
// submitter supplied both the digest and the fields, nothing would force them
// to agree, and a signature valid over a digest that contradicts the fields is
// a conviction path resting on attacker-supplied data.
//
// # Why this function is delicate
//
// The canonical form is a compact JSON array produced on the other side by a
// Rust tuple serialization. Three things must match exactly and none of them
// is enforced by a type:
//
//  1. HTML escaping is DISABLED. Go's encoding/json escapes <, > and & by
//     default; the Rust side does not. An organisation or tag containing an
//     ampersand would otherwise digest differently here — and would do so for
//     some inputs and not others, which is the worst failure shape available.
//  2. An absent roster is JSON null, not an omitted element. The field is an
//     optional on the other side and serialises as null, so the array is
//     always seven elements.
//  3. The signed message is this function's HEX STRING, not the 32 raw bytes.
//     Callers verifying a signature must sign over []byte(digest), not over
//     the decoded digest.
//
// A shared test vector pins all three. Do not change this function without
// regenerating it against the other implementation.
func EndorsementDigest(
	committeeParties uint64,
	sessionID uint64,
	params string,
	tag string,
	pkGSHA256 string,
	rosterSHA256 *string,
) (string, error) {
	tuple := []interface{}{
		EndorsementDomain,
		committeeParties,
		sessionID,
		params,
		tag,
		pkGSHA256,
		rosterSHA256,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tuple); err != nil {
		return "", fmt.Errorf("endorsement digest: canonicalise: %w", err)
	}
	// Encode appends a newline; the canonical form has none.
	canonical := bytes.TrimRight(buf.Bytes(), "\n")

	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
