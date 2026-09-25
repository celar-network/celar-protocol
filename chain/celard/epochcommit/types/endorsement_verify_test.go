package types_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cosmos/evm/evmd/epochcommit/types"
)

// The digest a quorum endorses. Its exact value is irrelevant here — what the
// signatures are over is pinned cross-language by testdata/endorsement/vector.json,
// and these tests are about the QUORUM rule, not the digest derivation.
const testDigest = "7776ed0925d4fb6f3c4f1b6f2a9c4b2e1d3c5a7e9f0b1d2c3e4f5a6b546e0374"

// seat is one roster member plus the private key the test signs with.
type seat struct {
	role uint32
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// newRoster builds n seats with deterministic keys, plus the canonical bytes
// and their digest.
//
// Determinism matters: a failure that only reproduces one run in ten is worse
// than no test. ed25519.NewKeyFromSeed gives a fixed key per seed.
func newRoster(t *testing.T, n int) ([]seat, []byte, string) {
	t.Helper()

	seats := make([]seat, 0, n)
	members := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i)
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		seats = append(seats, seat{role: uint32(i), pub: pub, priv: priv})
		members = append(members, fmt.Sprintf(
			`{"role":%d,"org":"org-%d","signing_pubkey":"%s"}`,
			i, i, hex.EncodeToString(pub),
		))
	}

	// Hand-written rather than marshalled, so the test does not verify Go's
	// encoder against itself. The producer's canonical form is compact JSON
	// with members sorted by role; the exact byte layout does not matter to
	// this verifier, because it hashes whatever it is given and compares
	// against the anchored value.
	b := []byte(fmt.Sprintf(
		`{"schema":"%s","mode":"Dev","tag":"t","params":"Test","members":[%s]}`,
		types.RosterSchema, strings.Join(members, ","),
	))
	sum := sha256.Sum256(b)
	return seats, b, hex.EncodeToString(sum[:])
}

// endorse signs the digest the way the producer does: over the HEX STRING
// bytes, not the 32 raw bytes.
func endorse(s seat, digest string) types.SeatEndorsement {
	return types.SeatEndorsement{
		Role:      s.role,
		Signature: ed25519.Sign(s.priv, []byte(digest)),
	}
}

func TestQuorumEndorsement_Accepts(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)

	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[1], testDigest),
		endorse(seats[2], testDigest),
	}
	if err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3); err != nil {
		t.Fatalf("a quorum of valid endorsements must be accepted: %v", err)
	}
}

// Everything below is a refusal case. They are the point of the file: the
// accept path proves the verifier can say yes, and only these prove it can
// say no — which is the half that makes the store safe to write to.

func TestQuorumEndorsement_RefusesTamperedRosterBytes(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)
	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[1], testDigest),
		endorse(seats[2], testDigest),
	}

	// One byte of an org name. The signatures are still valid and the quorum
	// is still met; only the anchor disagrees.
	tampered := []byte(strings.Replace(string(rosterBytes), "org-1", "org-X", 1))
	if len(tampered) != len(rosterBytes) {
		t.Fatal("test bug: the tamper changed the length, which is not the case under test")
	}

	err := types.VerifyQuorumEndorsement(tampered, rosterDigest, testDigest, e, 3)
	if err == nil {
		t.Fatal("roster bytes that do not hash to the anchored digest must be refused")
	}
	if !strings.Contains(err.Error(), "anchored digest") {
		t.Fatalf("refusal should name the anchor mismatch, got: %v", err)
	}
}

func TestQuorumEndorsement_RefusesSignatureOverRawDigestBytes(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)

	// The trap this signing scheme carries: the message is the hex STRING,
	// and signing the 32 decoded bytes instead produces a signature that is
	// perfectly valid over the wrong message. Both sides look correct in
	// isolation and every submission is rejected on chain.
	raw, err := hex.DecodeString(testDigest)
	if err != nil {
		t.Fatalf("test bug: %v", err)
	}
	e := []types.SeatEndorsement{
		{Role: seats[0].role, Signature: ed25519.Sign(seats[0].priv, raw)},
		endorse(seats[1], testDigest),
		endorse(seats[2], testDigest),
	}

	if err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3); err == nil {
		t.Fatal("a signature over the raw digest bytes must be refused, not accepted")
	}
}

func TestQuorumEndorsement_RefusesBelowQuorum(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)
	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[1], testDigest),
	}

	err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3)
	if err == nil {
		t.Fatal("two valid signatures must not satisfy a quorum of three")
	}
	if !strings.Contains(err.Error(), "quorum") {
		t.Fatalf("refusal should name the quorum, got: %v", err)
	}
}

func TestQuorumEndorsement_RefusesRepeatedRole(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)

	// One seat signing three times is one endorsement, not three.
	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[0], testDigest),
		endorse(seats[0], testDigest),
	}

	if err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3); err == nil {
		t.Fatal("one seat repeated must not reach a quorum of three")
	}
}

func TestQuorumEndorsement_RefusesUnrosteredRole(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)

	// A real key signing a real digest under a role the roster does not list.
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 0xAA
	outsider := ed25519.NewKeyFromSeed(seed)

	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[1], testDigest),
		{Role: 99, Signature: ed25519.Sign(outsider, []byte(testDigest))},
	}

	if err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3); err == nil {
		t.Fatal("a signature from outside the anchored roster must be refused")
	}
}

func TestQuorumEndorsement_RefusesWrongDigest(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)

	other := strings.Repeat("ab", 32)
	e := []types.SeatEndorsement{
		endorse(seats[0], other),
		endorse(seats[1], other),
		endorse(seats[2], other),
	}

	if err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3); err == nil {
		t.Fatal("signatures over a different transcript digest must be refused")
	}
}

func TestQuorumEndorsement_RefusesShortSignature(t *testing.T) {
	seats, rosterBytes, rosterDigest := newRoster(t, 5)
	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[1], testDigest),
		{Role: seats[2].role, Signature: []byte{0x01, 0x02}},
	}

	if err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, e, 3); err == nil {
		t.Fatal("a malformed signature must be refused on width before verification")
	}
}

func TestQuorumEndorsement_RefusesNonPositiveQuorum(t *testing.T) {
	_, rosterBytes, rosterDigest := newRoster(t, 5)

	// The failure this guards: a caller that computes the quorum from an
	// empty committee and gets zero would otherwise accept a submission
	// carrying no signatures at all.
	err := types.VerifyQuorumEndorsement(rosterBytes, rosterDigest, testDigest, nil, 0)
	if err == nil {
		t.Fatal("a quorum of zero must be refused, not treated as no requirement")
	}
}

func TestQuorumEndorsement_RefusesUnknownRosterSchema(t *testing.T) {
	seats, rosterBytes, _ := newRoster(t, 5)

	older := []byte(strings.Replace(
		string(rosterBytes), types.RosterSchema, "celar-committee-roster/v0", 1,
	))
	sum := sha256.Sum256(older)

	e := []types.SeatEndorsement{
		endorse(seats[0], testDigest),
		endorse(seats[1], testDigest),
		endorse(seats[2], testDigest),
	}

	// Anchored correctly, signatures valid, quorum met — refused purely on
	// the schema, because the previous schema does not commit to the signing
	// keys these signatures are checked against.
	err := types.VerifyQuorumEndorsement(older, hex.EncodeToString(sum[:]), testDigest, e, 3)
	if err == nil {
		t.Fatal("an unknown roster schema must be refused")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Fatalf("refusal should name the schema, got: %v", err)
	}
}

func TestQuorumEndorsement_RefusesSharedSigningKey(t *testing.T) {
	seats, _, _ := newRoster(t, 3)

	// Two roles, one key: one holder could otherwise supply two of the
	// quorum's signatures.
	pub := hex.EncodeToString(seats[0].pub)
	b := []byte(fmt.Sprintf(
		`{"schema":"%s","mode":"Dev","tag":"t","params":"Test","members":[`+
			`{"role":1,"org":"a","signing_pubkey":"%s"},`+
			`{"role":2,"org":"b","signing_pubkey":"%s"},`+
			`{"role":3,"org":"c","signing_pubkey":"%s"}]}`,
		types.RosterSchema, pub, pub, hex.EncodeToString(seats[2].pub),
	))
	sum := sha256.Sum256(b)

	e := []types.SeatEndorsement{
		{Role: 1, Signature: ed25519.Sign(seats[0].priv, []byte(testDigest))},
		{Role: 2, Signature: ed25519.Sign(seats[0].priv, []byte(testDigest))},
		endorse(seats[2], testDigest),
	}

	err := types.VerifyQuorumEndorsement(b, hex.EncodeToString(sum[:]), testDigest, e, 3)
	if err == nil {
		t.Fatal("a roster where two roles share a signing key must be refused")
	}
	if !strings.Contains(err.Error(), "share a signing key") {
		t.Fatalf("refusal should name the shared key, got: %v", err)
	}
}

func TestQuorumEndorsement_RefusesZeroRole(t *testing.T) {
	seats, _, _ := newRoster(t, 2)

	b := []byte(fmt.Sprintf(
		`{"schema":"%s","mode":"Dev","tag":"t","params":"Test","members":[`+
			`{"role":0,"org":"a","signing_pubkey":"%s"}]}`,
		types.RosterSchema, hex.EncodeToString(seats[0].pub),
	))
	sum := sha256.Sum256(b)

	err := types.VerifyQuorumEndorsement(b, hex.EncodeToString(sum[:]), testDigest, nil, 1)
	if err == nil {
		t.Fatal("role 0 is not a seat and a roster carrying it must be refused")
	}
}
