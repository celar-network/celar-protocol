package epochcommit

import (
	"github.com/cosmos/evm/evmd/epochcommit/keeper"
	"github.com/cosmos/evm/evmd/epochcommit/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// InitGenesis writes the archive, then the bounds.
//
// The order is NOT what protects the horizon, though it reads as if it should
// be. Verified by inverting it: the tests still pass, because SetCommitment
// only ever raises the upper bound and never lowers the lower one. The
// invariant lives there, and TestSetCommitmentNeverLowersTheHorizon pins it.
//
// The order is kept anyway as the one that reads correctly — entries, then
// the authoritative horizon — but a future change to SetCommitment's bound
// handling would break the property regardless of what this function does.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, gs *types.GenesisState) {
	for _, e := range gs.Entries {
		if err := k.SetCommitment(ctx, e.Epoch, e.SeatRole, e.Commitment); err != nil {
			panic(err)
		}
	}
	for _, h := range gs.Horizons {
		k.SetEpochHorizon(ctx, h.Epoch, h.ExpiryHeight)
	}
	for _, t := range gs.Transcripts {
		if err := k.SetTranscriptDigest(ctx, t.Epoch, t.Sha256); err != nil {
			panic(err)
		}
	}
	if gs.BoundsSet {
		k.InitBounds(ctx, gs.OldestRetainedEpoch, gs.LatestEpoch)
	}
}

func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	var entries []types.ArchiveEntry
	if err := k.IterateEntries(ctx, func(
		epoch uint64, role uint32, e types.ArchivedSeatCommitment,
	) bool {
		entries = append(entries, types.ArchiveEntry{
			Epoch: epoch, SeatRole: role, Commitment: e,
		})
		return true
	}); err != nil {
		panic(err)
	}
	var horizons []types.EpochHorizon
	if err := k.IterateHorizons(ctx, func(epoch, expiry uint64) bool {
		horizons = append(horizons, types.EpochHorizon{
			Epoch: epoch, ExpiryHeight: expiry,
		})
		return true
	}); err != nil {
		panic(err)
	}
	oldest, latest, ok := k.Bounds(ctx)
	var transcripts []types.TranscriptDigest
	if err := k.IterateTranscriptDigests(ctx, func(epoch uint64, d string) bool {
		transcripts = append(transcripts, types.TranscriptDigest{Epoch: epoch, Sha256: d})
		return true
	}); err != nil {
		panic(err)
	}
	gs := types.NewGenesisState(entries, ok, oldest, latest)
	gs.Horizons = horizons
	gs.Transcripts = transcripts
	return gs
}
