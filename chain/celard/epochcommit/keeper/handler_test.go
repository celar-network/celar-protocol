package keeper_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cosmos/evm/evmd/epochcommit/keeper"
	"github.com/cosmos/evm/evmd/epochcommit/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// The archive is a chain, so every handler test needs a previous epoch that
// the submission continues. These helpers build one.

const (
	prevDigest = "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899"
	newDigest  = "1122334455667788990011223344556677889900112233445566778899001122"
	testPkG    = "pkg-invariant"
)

type committee struct {
	privs        []ed25519.PrivateKey
	roles        []uint32
	canonical    []byte
	rosterDigest string
}

// newCommittee builds n seats with deterministic keys and the roster's
// canonical bytes.
func newCommittee(t *testing.T, n int) committee {
	t.Helper()
	c := committee{}
	members := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i)
		priv := ed25519.NewKeyFromSeed(seed)
		c.privs = append(c.privs, priv)
		c.roles = append(c.roles, uint32(i))
		members = append(members, fmt.Sprintf(
			`{"role":%d,"org":"org-%d","signing_pubkey":"%s"}`,
			i, i, hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
		))
	}
	c.canonical = []byte(fmt.Sprintf(
		`{"schema":"%s","mode":"Dev","tag":"t","params":"Test","members":[%s]}`,
		types.RosterSchema, strings.Join(members, ","),
	))
	sum := sha256.Sum256(c.canonical)
	c.rosterDigest = hex.EncodeToString(sum[:])
	return c
}

// quorum is what the handler will derive; the tests sign with exactly this
// many seats so that a change to the formula surfaces here rather than as a
// mysterious rejection.
func (c committee) quorum() int { return 3*len(c.privs)/4 + 1 }

func (c committee) endorse(digest string, count int) []types.SeatEndorsement {
	out := make([]types.SeatEndorsement, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, types.SeatEndorsement{
			Role:      c.roles[i],
			Signature: ed25519.Sign(c.privs[i], []byte(digest)),
		})
	}
	return out
}

func (c committee) entries() []types.ArchivedSeatCommitment {
	out := make([]types.ArchivedSeatCommitment, 0, len(c.roles))
	for i := range c.roles {
		out = append(out, types.ArchivedSeatCommitment{
			CommitmentSha256: fmt.Sprintf("commit-%d", i+1),
			RosterSha256:     c.rosterDigest,
			KeyedHeight:      200,
			PkGSha256:        testPkG,
		})
	}
	return out
}

// seedEpoch writes epoch 7 so a submission for epoch 8 has something to
// continue and something to anchor against.
func seedEpoch(t *testing.T, k keeper.Keeper, ctx sdk.Context, c committee) {
	t.Helper()
	for i, role := range c.roles {
		e := types.ArchivedSeatCommitment{
			CommitmentSha256: fmt.Sprintf("old-%d", i+1),
			RosterSha256:     c.rosterDigest,
			KeyedHeight:      100,
			PkGSha256:        testPkG,
		}
		if err := k.SetCommitment(ctx, 7, role, e); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := k.SetTranscriptDigest(ctx, 7, prevDigest); err != nil {
		t.Fatalf("seed digest: %v", err)
	}
}

func validMsg(c committee) *types.MsgSubmitEpochCommitments {
	return &types.MsgSubmitEpochCommitments{
		Submitter:            "celar1relayer",
		Epoch:                8,
		Entries:              c.entries(),
		SeatRoles:            c.roles,
		RosterCanonicalBytes: c.canonical,
		TranscriptDigest:     newDigest,
		PrevTranscriptDigest: prevDigest,
		Endorsements:         c.endorse(newDigest, c.quorum()),
	}
}

func setup(t *testing.T) (types.MsgServer, keeper.Keeper, sdk.Context, committee) {
	t.Helper()
	k, ctx := newKeeper(t)
	c := newCommittee(t, 8)
	seedEpoch(t, k, ctx, c)
	return keeper.NewMsgServerImpl(k), k, ctx, c
}

func TestSubmit_Accepts(t *testing.T) {
	srv, k, ctx, c := setup(t)

	resp, err := srv.SubmitEpochCommitments(ctx, validMsg(c))
	if err != nil {
		t.Fatalf("a quorum-endorsed submission continuing the chain must be accepted: %v", err)
	}
	if resp.AlreadyRecorded {
		t.Fatal("a first submission is not a duplicate")
	}

	got, found, err := k.GetCommitment(ctx, 8, 1)
	if err != nil || !found {
		t.Fatalf("epoch 8 seat 1 not archived: found=%v err=%v", found, err)
	}
	if got.CommitmentSha256 != "commit-1" {
		t.Fatalf("archived the wrong entry: %+v", got)
	}
	if d, ok := k.GetTranscriptDigest(ctx, 8); !ok || d != newDigest {
		t.Fatalf("transcript digest not stored: %q ok=%v", d, ok)
	}
}

func TestSubmit_IdenticalResubmissionReportsRatherThanErrors(t *testing.T) {
	srv, _, ctx, c := setup(t)

	if _, err := srv.SubmitEpochCommitments(ctx, validMsg(c)); err != nil {
		t.Fatalf("first: %v", err)
	}
	resp, err := srv.SubmitEpochCommitments(ctx, validMsg(c))
	if err != nil {
		t.Fatalf("at-least-once delivery makes duplicates ordinary; they must not error: %v", err)
	}
	if !resp.AlreadyRecorded {
		t.Fatal("a duplicate must be reported as already recorded, not silently re-stored")
	}
}

// The refusals. This is the half that makes the write path safe, and the
// reason the module stayed unregistered until it existed.

func TestSubmit_RefusesForgedSubmissionWithArbitraryCommitments(t *testing.T) {
	srv, _, ctx, c := setup(t)

	// The attack this whole path exists to stop: every structural input is
	// public, so an attacker composes a submission for the next epoch with
	// commitments of their choosing, copies the digests the chain already
	// holds, and satisfies every artifact check. Only the endorsements stop it.
	msg := validMsg(c)
	msg.Entries[0].CommitmentSha256 = "attacker-chosen"
	msg.Endorsements = nil

	if _, err := srv.SubmitEpochCommitments(ctx, msg); err == nil {
		t.Fatal("a submission with no endorsements must be refused whatever else checks out")
	}
}

func TestSubmit_RefusesBelowQuorumEvenWithValidSignatures(t *testing.T) {
	srv, _, ctx, c := setup(t)

	msg := validMsg(c)
	msg.Endorsements = c.endorse(newDigest, c.quorum()-1)

	if _, err := srv.SubmitEpochCommitments(ctx, msg); err == nil {
		t.Fatal("one short of the reconstruction quorum must be refused")
	}
}

func TestSubmit_RefusesEpochGap(t *testing.T) {
	srv, _, ctx, c := setup(t)

	msg := validMsg(c)
	msg.Epoch = 9 // skips 8

	if _, err := srv.SubmitEpochCommitments(ctx, msg); err == nil {
		t.Fatal("an epoch gap must be refused: it makes absence undecidable for everything after it")
	}
}

func TestSubmit_RefusesBrokenTranscriptChain(t *testing.T) {
	srv, _, ctx, c := setup(t)

	msg := validMsg(c)
	msg.PrevTranscriptDigest = strings.Repeat("00", 32)

	if _, err := srv.SubmitEpochCommitments(ctx, msg); err == nil {
		t.Fatal("a submission that does not chain from the stored digest must be refused")
	}
}

func TestSubmit_RefusesChangedPkG(t *testing.T) {
	srv, _, ctx, c := setup(t)

	msg := validMsg(c)
	for i := range msg.Entries {
		msg.Entries[i].PkGSha256 = "different-key"
	}

	if _, err := srv.SubmitEpochCommitments(ctx, msg); err == nil {
		t.Fatal("pk_G is invariant across epochs; a change means a different key and must be refused")
	}
}

func TestSubmit_RefusesRosterRotation(t *testing.T) {
	srv, _, ctx, c := setup(t)

	// A different committee, correctly self-consistent: its own canonical
	// bytes, its own digest in its own entries, its own valid signatures.
	// Everything agrees with everything except the chain's anchor.
	other := newCommittee(t, 8)
	other.privs[0] = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	other = rebuild(t, other)

	msg := validMsg(c)
	msg.Entries = other.entries()
	msg.RosterCanonicalBytes = other.canonical
	msg.Endorsements = other.endorse(newDigest, other.quorum())

	_, err := srv.SubmitEpochCommitments(ctx, msg)
	if err == nil {
		t.Fatal("an unanchored roster must be refused: otherwise a submitter supplies both the keys and the signatures over them")
	}
	if !strings.Contains(err.Error(), "rotation is not implemented") {
		t.Fatalf("the refusal should say rotation is unimplemented rather than look like a bug: %v", err)
	}
}

func TestSubmit_RefusesMismatchedRolesAndEntries(t *testing.T) {
	srv, _, ctx, c := setup(t)

	msg := validMsg(c)
	msg.SeatRoles = msg.SeatRoles[:len(msg.SeatRoles)-1]

	if _, err := srv.SubmitEpochCommitments(ctx, msg); err == nil {
		t.Fatal("entries and roles must pair positionally; a mismatch would renumber seats")
	}
}

func TestSubmit_RefusesIntoUninitialisedArchive(t *testing.T) {
	k, ctx := newKeeper(t)
	c := newCommittee(t, 8)
	srv := keeper.NewMsgServerImpl(k)

	// No genesis anchor. Accepting here would let a submitter choose the
	// epoch everything else chains from.
	if _, err := srv.SubmitEpochCommitments(ctx, validMsg(c)); err == nil {
		t.Fatal("a write into an unanchored archive must be refused")
	}
}

// rebuild recomputes the canonical bytes and digest after a key was swapped.
func rebuild(t *testing.T, c committee) committee {
	t.Helper()
	members := make([]string, 0, len(c.privs))
	for i, p := range c.privs {
		members = append(members, fmt.Sprintf(
			`{"role":%d,"org":"org-%d","signing_pubkey":"%s"}`,
			i+1, i+1, hex.EncodeToString(p.Public().(ed25519.PublicKey)),
		))
	}
	c.canonical = []byte(fmt.Sprintf(
		`{"schema":"%s","mode":"Dev","tag":"t","params":"Test","members":[%s]}`,
		types.RosterSchema, strings.Join(members, ","),
	))
	sum := sha256.Sum256(c.canonical)
	c.rosterDigest = hex.EncodeToString(sum[:])
	return c
}
