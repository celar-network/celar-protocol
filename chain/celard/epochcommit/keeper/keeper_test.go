package keeper_test

import (
	"testing"

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

func entry(c string) types.ArchivedSeatCommitment {
	return types.ArchivedSeatCommitment{
		CommitmentSha256: c,
		RosterSha256:     "roster",
		KeyedHeight:      100,
		PkGSha256:        "pkg",
	}
}

func TestSetAndGet(t *testing.T) {
	k, ctx := newKeeper(t)
	if err := k.SetCommitment(ctx, 5, 3, entry("c53")); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, found, err := k.GetCommitment(ctx, 5, 3)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.CommitmentSha256 != "c53" || got.KeyedHeight != 100 {
		t.Fatalf("round-trip lost data: %+v", got)
	}
	if _, found, _ := k.GetCommitment(ctx, 5, 4); found {
		t.Fatal("a seat that was never written reports as present")
	}
}

func TestSeatRoleZeroRefusedOnBothPaths(t *testing.T) {
	k, ctx := newKeeper(t)
	if err := k.SetCommitment(ctx, 1, 0, entry("x")); err == nil {
		t.Fatal("wrote an entry at seat role 0")
	}
	if _, _, err := k.GetCommitment(ctx, 1, 0); err == nil {
		t.Fatal("read at seat role 0 returned a miss rather than an error")
	}
}

// An all-default entry encodes to zero bytes, which is byte-identical to a
// missing key. Writing one would turn a real record into an anomalous gap at
// the verifier, so the store refuses.
func TestEmptyEntryRefused(t *testing.T) {
	k, ctx := newKeeper(t)
	if err := k.SetCommitment(ctx, 1, 1, types.ArchivedSeatCommitment{}); err == nil {
		t.Fatal("wrote an entry indistinguishable from absence")
	}
}

func TestBoundsTrackWrites(t *testing.T) {
	k, ctx := newKeeper(t)
	if _, _, ok := k.Bounds(ctx); ok {
		t.Fatal("bounds initialised before any write")
	}
	_ = k.SetCommitment(ctx, 7, 1, entry("a"))
	oldest, latest, ok := k.Bounds(ctx)
	if !ok || oldest != 7 || latest != 7 {
		t.Fatalf("first write should set both bounds, got (%d,%d,%v)", oldest, latest, ok)
	}
	_ = k.SetCommitment(ctx, 9, 1, entry("b"))
	oldest, latest, _ = k.Bounds(ctx)
	if oldest != 7 || latest != 9 {
		t.Fatalf("later epoch should move only the upper bound, got (%d,%d)", oldest, latest)
	}
}

// THE ORDERING PROPERTY. The horizon must advance before deletion, so a read
// taken mid-sweep reports time-barred rather than anomaly. Expired exonerates;
// anomaly does not, and a partially-swept store must not accuse anyone.
func TestPruneAdvancesTheBoundBeforeDeleting(t *testing.T) {
	k, ctx := newKeeper(t)
	for e := uint64(1); e <= 6; e++ {
		for role := uint32(1); role <= 3; role++ {
			if err := k.SetCommitment(ctx, e, role, entry("x")); err != nil {
				t.Fatalf("set: %v", err)
			}
		}
	}
	// Deliberately too small to finish: 9 entries lie below epoch 4.
	deleted := k.PruneBelow(ctx, 4, 2)
	if deleted != 2 {
		t.Fatalf("expected a bounded sweep of 2, got %d", deleted)
	}
	oldest, _, _ := k.Bounds(ctx)
	if oldest != 4 {
		t.Fatalf("horizon did not advance ahead of deletion, oldest=%d", oldest)
	}
	// An entry still physically present below the horizon must already read
	// as time-barred by the bounds, not as an anomaly.
	if _, found, _ := k.GetCommitment(ctx, 1, 3); !found {
		t.Fatal("precondition: expected an undeleted entry to remain")
	}
	if oldest <= 1 {
		t.Fatal("an undeleted entry below the horizon is not yet time-barred")
	}
}

// The property that actually protects the retention horizon. Writing an entry
// inside the retained range must not drag the lower bound down to it: evidence
// from an already-pruned epoch has to keep reading as time-barred, which
// exonerates, rather than as never-established, which accuses.
//
// This was written after a mutation check showed the test it replaces could
// not fail — the ordering it claimed to verify turned out not to matter, and
// this guard is what does the work.
func TestSetCommitmentNeverLowersTheHorizon(t *testing.T) {
	k, ctx := newKeeper(t)
	k.InitBounds(ctx, 5, 9)

	if err := k.SetCommitment(ctx, 7, 1, entry("a")); err != nil {
		t.Fatalf("set: %v", err)
	}
	oldest, latest, _ := k.Bounds(ctx)
	if oldest != 5 {
		t.Fatalf("writing epoch 7 lowered the horizon to %d", oldest)
	}
	if latest != 9 {
		t.Fatalf("writing inside the range moved the upper bound to %d", latest)
	}

	// And a write above the range does raise the upper bound.
	if err := k.SetCommitment(ctx, 12, 1, entry("b")); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, latest, _ = k.Bounds(ctx); latest != 12 {
		t.Fatalf("a newer epoch did not raise the upper bound, latest=%d", latest)
	}
}
