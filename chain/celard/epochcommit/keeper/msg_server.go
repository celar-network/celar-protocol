package keeper

import (
	"context"
	"fmt"

	"github.com/cosmos/evm/evmd/epochcommit/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type msgServer struct {
	k Keeper
}

// NewMsgServerImpl returns the message service backed by this keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer {
	return &msgServer{k: k}
}

var _ types.MsgServer = (*msgServer)(nil)

// SubmitEpochCommitments archives one epoch's per-seat commitments.
//
// The submitter is a relayer, not an authority. What authenticates the write is
// a reconstruction quorum of rostered seats signing the transcript's
// endorsement digest — because the structural checks below cannot: every input
// to them is public, so a submission carrying arbitrary commitments satisfies
// all of them. A hash chain establishes order and continuity, never authorship.
//
// Order matters and is cheapest-first, which is also safest-first: the epoch is
// resolved before any signature work, so a submission for a stale or future
// epoch never becomes a signature probe.
func (m msgServer) SubmitEpochCommitments(
	goCtx context.Context,
	msg *types.MsgSubmitEpochCommitments,
) (*types.MsgSubmitEpochCommitmentsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if len(msg.Entries) == 0 {
		return nil, fmt.Errorf("epochcommit: submission carries no entries")
	}
	if len(msg.Entries) != len(msg.SeatRoles) {
		// Positional pairing is the interface; a length mismatch would
		// silently renumber seats, and a renumbered seat convicts the wrong
		// party.
		return nil, fmt.Errorf(
			"epochcommit: %d entries against %d seat roles",
			len(msg.Entries), len(msg.SeatRoles),
		)
	}

	// Idempotence is resolved BEFORE continuity, and the order is the whole
	// point rather than a tidying preference.
	//
	// A resubmission of an already-archived epoch is not a continuation: it
	// fails `epoch == latest+1` by construction, because that epoch IS the
	// latest. Checking continuity first made this branch unreachable and
	// answered an ordinary duplicate with "does not continue the archive" —
	// which a relayer reads as a permanent failure or retries forever, the
	// exact behaviour reporting duplicates exists to prevent. A test caught
	// it; nothing about the code looked wrong.
	if existing, ok := m.k.GetTranscriptDigest(ctx, msg.Epoch); ok {
		if existing != msg.TranscriptDigest {
			return nil, fmt.Errorf(
				"epochcommit: epoch %d is already archived under transcript %q",
				msg.Epoch, existing,
			)
		}
		// ⚠️ The limit of this, stated rather than implied: the chain matches
		// the TRANSCRIPT DIGEST, not the entries. Check (i) of the artifact
		// checks — that the commitments are exactly the transcript's
		// commitments section — is not implementable here, because the chain
		// holds the digest and never the transcript. So a resubmission under a
		// matching digest is reported as a duplicate without re-verifying its
		// contents; what binds contents to that digest is the ceremony, and
		// the endorsements are what make the digest trustworthy.
		return &types.MsgSubmitEpochCommitmentsResponse{AlreadyRecorded: true}, nil
	}

	// (v) The epoch must continue the chain exactly.
	oldest, latest, initialised := m.k.Bounds(ctx)
	if !initialised {
		// Epoch 0 is anchored at genesis. Accepting a runtime write into an
		// empty archive would let a submitter choose the anchor everything
		// else chains from.
		return nil, fmt.Errorf("epochcommit: archive is not initialised; genesis anchors the first epoch")
	}
	if msg.Epoch != latest+1 {
		return nil, fmt.Errorf(
			"epochcommit: epoch %d does not continue the archive (latest is %d)",
			msg.Epoch, latest,
		)
	}
	_ = oldest

	// (ii) The transcript chain.
	prev, ok := m.k.GetTranscriptDigest(ctx, msg.Epoch-1)
	if !ok {
		return nil, fmt.Errorf(
			"epochcommit: no transcript digest stored for epoch %d, so epoch %d cannot chain from it",
			msg.Epoch-1, msg.Epoch,
		)
	}
	if msg.PrevTranscriptDigest != prev {
		return nil, fmt.Errorf(
			"epochcommit: submission chains from %q but epoch %d recorded %q",
			msg.PrevTranscriptDigest, msg.Epoch-1, prev,
		)
	}
	if msg.TranscriptDigest == "" {
		return nil, fmt.Errorf("epochcommit: transcript digest is empty")
	}

	// (iii)/(iv) The entries must agree with each other on the two invariants
	// before either is compared with the archive. An internally inconsistent
	// submission is malformed, and checking it here means the comparison below
	// has one value to make rather than a set.
	rosterSHA := msg.Entries[0].RosterSha256
	pkG := msg.Entries[0].PkGSha256
	for i, e := range msg.Entries {
		if e.RosterSha256 != rosterSHA {
			return nil, fmt.Errorf("epochcommit: entry %d names a different roster digest", i)
		}
		if e.PkGSha256 != pkG {
			return nil, fmt.Errorf("epochcommit: entry %d names a different pk_G digest", i)
		}
		if e.CommitmentSha256 == "" {
			return nil, fmt.Errorf("epochcommit: entry %d has an empty commitment", i)
		}
	}

	// The anchors come from the previous epoch, which is chain state rather
	// than submission content.
	anchor, ok, err := m.k.GetCommitment(ctx, msg.Epoch-1, msg.SeatRoles[0])
	if err != nil {
		// A stored entry that does not decode, or an invalid seat role. Both
		// are errors rather than absences, and the store separates them from a
		// miss deliberately — conflating them is what makes an anomaly read as
		// a pruned epoch.
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf(
			"epochcommit: epoch %d has no entry for seat %d to anchor against",
			msg.Epoch-1, msg.SeatRoles[0],
		)
	}
	if pkG != anchor.PkGSha256 {
		// pk_G is invariant across epochs by construction; a change means the
		// submission belongs to a different key.
		return nil, fmt.Errorf(
			"epochcommit: pk_G digest %q does not match the archived %q",
			pkG, anchor.PkGSha256,
		)
	}
	if rosterSHA != anchor.RosterSha256 {
		// 🔴 Committee rotation is NOT implemented, and this refuses rather
		// than guessing.
		//
		// The chain only ever anchors the previous epoch's roster, so a
		// membership change makes this submission carry a roster the chain has
		// never seen, and no check here can distinguish a legitimate rotation
		// from a substituted roster. The natural answer — a roster change
		// endorsed by the outgoing quorum — is a second design that nobody has
		// specified.
		//
		// Accepting the new digest on the submitter's word would make the
		// endorsement check meaningless: an attacker would supply their own
		// roster and their own signatures over it.
		return nil, fmt.Errorf(
			"epochcommit: roster digest changed from %q to %q — committee rotation is not "+
				"implemented, and accepting an unanchored roster would let a submitter "+
				"supply both the keys and the signatures",
			anchor.RosterSha256, rosterSHA,
		)
	}

	// Only now, the expensive part: who endorsed it.
	quorum, err := types.ReconstructionQuorum(msg.RosterCanonicalBytes)
	if err != nil {
		return nil, err
	}
	if err := types.VerifyQuorumEndorsement(
		msg.RosterCanonicalBytes, rosterSHA, msg.TranscriptDigest, msg.Endorsements, quorum,
	); err != nil {
		return nil, err
	}

	for i, e := range msg.Entries {
		if err := m.k.SetCommitment(ctx, msg.Epoch, msg.SeatRoles[i], e); err != nil {
			return nil, err
		}
	}
	if err := m.k.SetTranscriptDigest(ctx, msg.Epoch, msg.TranscriptDigest); err != nil {
		return nil, err
	}

	return &types.MsgSubmitEpochCommitmentsResponse{AlreadyRecorded: false}, nil
}
