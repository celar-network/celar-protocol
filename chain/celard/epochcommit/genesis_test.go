package epochcommit_test

import (
	"testing"

	"github.com/cosmos/evm/evmd/epochcommit"
	"github.com/cosmos/evm/evmd/epochcommit/keeper"
	"github.com/cosmos/evm/evmd/epochcommit/types"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func newKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	tKey := storetypes.NewTransientStoreKey("transient_test")
	ctx := testutil.DefaultContext(storeKey, tKey) //nolint: staticcheck
	return keeper.NewKeeper(storeKey), ctx
}

func commitment(c string) types.ArchivedSeatCommitment {
	return types.ArchivedSeatCommitment{
		CommitmentSha256: c, RosterSha256: "r", KeyedHeight: 42, PkGSha256: "k",
	}
}

func TestGenesisRoundTrips(t *testing.T) {
	k, ctx := newKeeper(t)
	in := types.NewGenesisState([]types.ArchiveEntry{
		{Epoch: 7, SeatRole: 1, Commitment: commitment("a")},
		{Epoch: 7, SeatRole: 2, Commitment: commitment("b")},
		{Epoch: 9, SeatRole: 1, Commitment: commitment("c")},
	}, true, 7, 9)
	if err := in.Validate(); err != nil {
		t.Fatalf("fixture is not a valid genesis: %v", err)
	}
	epochcommit.InitGenesis(ctx, k, in)
	out := epochcommit.ExportGenesis(ctx, k)
	if len(out.Entries) != 3 || !out.BoundsSet ||
		out.OldestRetainedEpoch != 7 || out.LatestEpoch != 9 {
		t.Fatalf("round trip changed the archive: %+v", out)
	}
}

// THE ORDERING CASE. An archive whose older epochs were pruned carries a
// horizon ABOVE nothing it still holds — here 5, while the oldest surviving
// entry is 7. Writing entries moves the bounds, so if the horizon were
// written first it would be overwritten to 7, and evidence from epochs 5 and
// 6 would flip from time-barred (exonerating) to never-established (a forgery
// finding against an honest accuser).
func TestPrunedHorizonSurvivesImport(t *testing.T) {
	k, ctx := newKeeper(t)
	in := types.NewGenesisState([]types.ArchiveEntry{
		{Epoch: 7, SeatRole: 1, Commitment: commitment("a")},
		{Epoch: 9, SeatRole: 1, Commitment: commitment("b")},
	}, true, 5, 9)
	if err := in.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	epochcommit.InitGenesis(ctx, k, in)

	oldest, latest, ok := k.Bounds(ctx)
	if !ok || oldest != 5 || latest != 9 {
		t.Fatalf("horizon did not survive import: got (%d,%d,%v), want (5,9,true)",
			oldest, latest, ok)
	}
}

// A fully pruned archive is entries-free but still remembers its horizon.
func TestFullyPrunedArchiveRoundTrips(t *testing.T) {
	k, ctx := newKeeper(t)
	in := types.NewGenesisState(nil, true, 9, 9)
	if err := in.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	epochcommit.InitGenesis(ctx, k, in)
	out := epochcommit.ExportGenesis(ctx, k)
	if len(out.Entries) != 0 || !out.BoundsSet ||
		out.OldestRetainedEpoch != 9 || out.LatestEpoch != 9 {
		t.Fatalf("a pruned archive lost its horizon: %+v", out)
	}
}

func TestValidateRejectsEntriesWithoutBounds(t *testing.T) {
	gs := types.NewGenesisState([]types.ArchiveEntry{
		{Epoch: 1, SeatRole: 1, Commitment: commitment("a")},
	}, false, 0, 0)
	if err := gs.Validate(); err == nil {
		t.Fatal("accepted entries with no retention bounds")
	}
}

func TestDefaultGenesisIsValidAndEmpty(t *testing.T) {
	gs := types.DefaultGenesisState()
	if err := gs.Validate(); err != nil {
		t.Fatalf("default genesis rejected: %v", err)
	}
	if gs.BoundsSet || len(gs.Entries) != 0 {
		t.Fatal("default genesis is not an empty, boundless archive")
	}
}

// Horizons must survive export and import. Without them a restored chain
// cannot prune, and — worse — cannot show why it is not pruning: every epoch
// would look like one whose horizon was never recorded.
func TestHorizonsSurviveRoundTrip(t *testing.T) {
	k, ctx := newKeeper(t)
	in := types.NewGenesisState([]types.ArchiveEntry{
		{Epoch: 4, SeatRole: 1, Commitment: commitment("a")},
	}, true, 4, 4)
	in.Horizons = []types.EpochHorizon{
		{Epoch: 4, ExpiryHeight: 9000},
	}
	if err := in.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	epochcommit.InitGenesis(ctx, k, in)

	if h, ok := k.GetEpochHorizon(ctx, 4); !ok || h != 9000 {
		t.Fatalf("horizon not imported: got %d ok=%v", h, ok)
	}
	out := epochcommit.ExportGenesis(ctx, k)
	if len(out.Horizons) != 1 || out.Horizons[0].ExpiryHeight != 9000 {
		t.Fatalf("horizon lost on export: %+v", out.Horizons)
	}
}

// Transcript digests must survive export and import. Without them a restored
// chain cannot check the linkage of a submission against the epoch before it,
// and would have to either refuse everything or accept anything.
func TestTranscriptDigestsSurviveRoundTrip(t *testing.T) {
	k, ctx := newKeeper(t)
	in := types.NewGenesisState([]types.ArchiveEntry{
		{Epoch: 4, SeatRole: 1, Commitment: commitment("a")},
	}, true, 4, 4)
	in.Transcripts = []types.TranscriptDigest{{Epoch: 4, Sha256: "abc123"}}
	if err := in.Validate(); err != nil {
		t.Fatalf("fixture invalid: %v", err)
	}
	epochcommit.InitGenesis(ctx, k, in)

	if d, ok := k.GetTranscriptDigest(ctx, 4); !ok || d != "abc123" {
		t.Fatalf("digest not imported: %q ok=%v", d, ok)
	}
	out := epochcommit.ExportGenesis(ctx, k)
	if len(out.Transcripts) != 1 || out.Transcripts[0].Sha256 != "abc123" {
		t.Fatalf("digest lost on export: %+v", out.Transcripts)
	}
}
