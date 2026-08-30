package keeper_test

import "testing"

// The sweep advances past epochs whose horizon has passed, and stops at the
// first that has not.
func TestPruneExpiredAdvancesToTheFirstLiveEpoch(t *testing.T) {
	k, ctx := newKeeper(t)
	for e := uint64(1); e <= 5; e++ {
		if err := k.SetCommitment(ctx, e, 1, entry("x")); err != nil {
			t.Fatalf("set: %v", err)
		}
		k.SetEpochHorizon(ctx, e, e*100) // epoch 1 expires at 100, 2 at 200, ...
	}
	// At height 250, epochs 1 and 2 are past their horizon; 3 is not.
	advanced, _ := k.PruneExpired(ctx, 250, 100)
	if advanced != 3 {
		t.Fatalf("expected the bound at 3, got %d", advanced)
	}
	oldest, _, _ := k.Bounds(ctx)
	if oldest != 3 {
		t.Fatalf("bound not persisted, oldest=%d", oldest)
	}
}

// An epoch with no recorded horizon stops the sweep. Retaining evidence too
// long costs storage; discarding it early destroys punishability and would
// present as time-barred, which exonerates.
func TestUnknownHorizonStopsTheSweep(t *testing.T) {
	k, ctx := newKeeper(t)
	for e := uint64(1); e <= 4; e++ {
		_ = k.SetCommitment(ctx, e, 1, entry("x"))
	}
	k.SetEpochHorizon(ctx, 1, 10)
	// epoch 2 deliberately has no horizon
	k.SetEpochHorizon(ctx, 3, 10)

	advanced, _ := k.PruneExpired(ctx, 1_000_000, 100)
	if advanced != 2 {
		t.Fatalf("swept past an epoch with no horizon: advanced to %d", advanced)
	}
}

// The newest epoch is never pruned, even if its horizon has passed: an
// archive whose bound passed its latest epoch would report every epoch as
// both time-barred and never-established.
func TestLatestEpochIsNeverPruned(t *testing.T) {
	k, ctx := newKeeper(t)
	for e := uint64(1); e <= 3; e++ {
		_ = k.SetCommitment(ctx, e, 1, entry("x"))
		k.SetEpochHorizon(ctx, e, 1)
	}
	advanced, _ := k.PruneExpired(ctx, 1_000_000, 100)
	if advanced != 3 {
		t.Fatalf("expected the bound to stop at the latest epoch, got %d", advanced)
	}
	oldest, latest, _ := k.Bounds(ctx)
	if oldest > latest {
		t.Fatalf("bound passed the latest epoch: oldest=%d latest=%d", oldest, latest)
	}
}

func TestPruneExpiredIsANoOpBeforeAnyHorizonPasses(t *testing.T) {
	k, ctx := newKeeper(t)
	_ = k.SetCommitment(ctx, 1, 1, entry("x"))
	k.SetEpochHorizon(ctx, 1, 5_000)
	advanced, deleted := k.PruneExpired(ctx, 10, 100)
	if advanced != 1 || deleted != 0 {
		t.Fatalf("swept before anything expired: advanced=%d deleted=%d", advanced, deleted)
	}
}
