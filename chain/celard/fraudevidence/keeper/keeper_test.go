package keeper_test

import (
	"testing"

	"github.com/cosmos/evm/evmd/fraudevidence/keeper"
	"github.com/cosmos/evm/evmd/fraudevidence/types"

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

func verdict(evidence string) types.Verdict {
	return types.Verdict{
		SeatRole:       3,
		Epoch:          5,
		EvidenceSha256: evidence,
		RecordedHeight: 100,
	}
}

func TestRecordAndRead(t *testing.T) {
	k, ctx := newKeeper(t)
	existed, err := k.RecordVerdict(ctx, verdict("e1"))
	if err != nil || existed {
		t.Fatalf("record: existed=%v err=%v", existed, err)
	}
	got, found, err := k.Verdict(ctx, 5, 3)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if got.EvidenceSha256 != "e1" || got.RecordedHeight != 100 {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if got.Punished {
		t.Fatal("a fresh verdict must not read as punished")
	}
}

// Anyone may submit, so two people racing to submit the same proof is
// ordinary. The second must be a no-op rather than an error or a second
// conviction.
func TestResubmittingTheSameEvidenceIsANoOp(t *testing.T) {
	k, ctx := newKeeper(t)
	if _, err := k.RecordVerdict(ctx, verdict("e1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	later := verdict("e1")
	later.RecordedHeight = 999
	existed, err := k.RecordVerdict(ctx, later)
	if err != nil || !existed {
		t.Fatalf("second: existed=%v err=%v", existed, err)
	}
	got, _, _ := k.Verdict(ctx, 5, 3)
	if got.RecordedHeight != 100 {
		t.Fatalf("resubmission moved the recorded height to %d; the first "+
			"record is when the chain acted", got.RecordedHeight)
	}
}

// A second conviction of the same seat and epoch on DIFFERENT evidence is a
// separate fact. Overwriting would erase the record a slash was applied
// against, so it is refused rather than accepted quietly.
func TestConflictingEvidenceIsRefusedRatherThanOverwriting(t *testing.T) {
	k, ctx := newKeeper(t)
	if _, err := k.RecordVerdict(ctx, verdict("e1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := k.RecordVerdict(ctx, verdict("e2"))
	if err != types.ErrConflictingVerdict {
		t.Fatalf("expected refusal, got %v", err)
	}
	got, _, _ := k.Verdict(ctx, 5, 3)
	if got.EvidenceSha256 != "e1" {
		t.Fatal("the original record must survive a conflicting submission")
	}
}

// Roles are one-based by interface agreement. Zero is malformed evidence,
// and a lookup that merely missed would be indistinguishable from a verdict
// that was never recorded.
func TestSeatRoleZeroIsRefused(t *testing.T) {
	k, ctx := newKeeper(t)
	v := verdict("e1")
	v.SeatRole = 0
	if _, err := k.RecordVerdict(ctx, v); err != types.ErrInvalidSeatRole {
		t.Fatalf("expected the one-based rule to refuse, got %v", err)
	}
}

func TestPunishmentIsRecordedOnceAndOnlyForRealVerdicts(t *testing.T) {
	k, ctx := newKeeper(t)
	if err := k.MarkPunished(ctx, 5, 3); err != types.ErrNoSuchVerdict {
		t.Fatalf("punishing a verdict that does not exist must refuse, got %v", err)
	}
	if _, err := k.RecordVerdict(ctx, verdict("e1")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := k.MarkPunished(ctx, 5, 3); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := k.MarkPunished(ctx, 5, 3); err != nil {
		t.Fatalf("marking twice must be a no-op, got %v", err)
	}
	got, _, _ := k.Verdict(ctx, 5, 3)
	if !got.Punished {
		t.Fatal("punishment did not persist")
	}
}
