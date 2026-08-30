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
	oldest, latest, ok := k.Bounds(ctx)
	return types.NewGenesisState(entries, ok, oldest, latest)
}
