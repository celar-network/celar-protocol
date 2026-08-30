package keeper

import (
	"encoding/binary"
	"fmt"

	"github.com/cosmos/evm/evmd/epochcommit/types"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper owns the per-epoch commitment archive: one entry per (epoch, seat),
// plus two bounds that are never pruned.
//
// The KMS reads this store through ICS23 to verify accountability evidence
// after a reshare has replaced every live commitment. It is written by chain
// logic and read by an off-chain verifier, which is why it is a native module
// rather than precompile storage.
// No codec: entries marshal themselves under the canonical field numbers,
// and a codec here would be an unused dependency that later invites a second
// encoding path. One definition of the bytes is the whole point.
type Keeper struct {
	storeKey storetypes.StoreKey
}

func NewKeeper(storeKey storetypes.StoreKey) Keeper {
	return Keeper{storeKey: storeKey}
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func readU64(bz []byte) (uint64, bool) {
	if len(bz) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(bz), true
}

// Bounds returns (oldest_retained_epoch, latest_epoch). Both survive pruning,
// and together they make absence decidable: below the first is time-barred,
// above the second never existed, in between is an anomaly. A missing key
// alone cannot separate those three, and conflating them lets expired
// evidence read as forged, or forged evidence read as expired.
func (k Keeper) Bounds(ctx sdk.Context) (oldest uint64, latest uint64, initialised bool) {
	store := ctx.KVStore(k.storeKey)
	o, okO := readU64(store.Get(types.OldestRetainedEpochKey))
	l, okL := readU64(store.Get(types.LatestEpochKey))
	return o, l, okO && okL
}

func (k Keeper) setBounds(ctx sdk.Context, oldest, latest uint64) {
	store := ctx.KVStore(k.storeKey)
	store.Set(types.OldestRetainedEpochKey, u64(oldest))
	store.Set(types.LatestEpochKey, u64(latest))
}

// SetCommitment records one seat's commitment for one epoch.
//
// Refuses an entry that encodes to zero bytes. In proto3 an all-default
// message encodes empty, so a written-but-empty entry would be byte-identical
// to a missing key — which would turn a real entry into an "anomalous gap"
// for the verifier. The store must never create that ambiguity.
func (k Keeper) SetCommitment(
	ctx sdk.Context,
	epoch uint64,
	seatRole uint32,
	entry types.ArchivedSeatCommitment,
) error {
	key, err := types.EntryKey(epoch, seatRole)
	if err != nil {
		return err
	}
	bz, err := entry.Marshal()
	if err != nil {
		return fmt.Errorf("marshal entry (epoch %d, seat %d): %w", epoch, seatRole, err)
	}
	if len(bz) == 0 {
		return fmt.Errorf(
			"refusing to write an empty entry for epoch %d seat %d: it would "+
				"be indistinguishable from an absent one", epoch, seatRole)
	}

	store := ctx.KVStore(k.storeKey)
	store.Set(key, bz)

	oldest, latest, ok := k.Bounds(ctx)
	switch {
	case !ok:
		// First write establishes both bounds.
		k.setBounds(ctx, epoch, epoch)
	case epoch > latest:
		k.setBounds(ctx, oldest, epoch)
	}
	return nil
}

// GetCommitment reads one seat's entry. The bool distinguishes absent from
// present; callers resolve *why* it is absent through Bounds, not by guessing
// from the miss.
func (k Keeper) GetCommitment(
	ctx sdk.Context,
	epoch uint64,
	seatRole uint32,
) (types.ArchivedSeatCommitment, bool, error) {
	var entry types.ArchivedSeatCommitment
	key, err := types.EntryKey(epoch, seatRole)
	if err != nil {
		return entry, false, err
	}
	bz := ctx.KVStore(k.storeKey).Get(key)
	if len(bz) == 0 {
		return entry, false, nil
	}
	if err := entry.Unmarshal(bz); err != nil {
		return entry, false, fmt.Errorf(
			"stored entry for epoch %d seat %d does not decode: %w",
			epoch, seatRole, err)
	}
	return entry, true, nil
}

// PruneBelow advances the retention horizon and then deletes, in that order.
//
// The order is the point. "Expired" is a verdict that exonerates, so a read
// taken during the sweep must return time-barred rather than anomaly: the
// bound moves first, and deletion is allowed to lag. Deletion is bounded per
// call so a sweep cannot stall a block; whatever remains is deleted next time,
// and is already correctly reported as time-barred meanwhile.
func (k Keeper) PruneBelow(ctx sdk.Context, newOldest uint64, maxDeletes int) (deleted int) {
	oldest, latest, ok := k.Bounds(ctx)
	if !ok || newOldest <= oldest {
		return 0
	}
	if newOldest > latest {
		newOldest = latest
	}
	k.setBounds(ctx, newOldest, latest)

	store := ctx.KVStore(k.storeKey)
	it := storetypes.KVStorePrefixIterator(store, types.EntryPrefix)
	defer it.Close()
	var stale [][]byte
	for ; it.Valid() && len(stale) < maxDeletes; it.Next() {
		key := it.Key()
		if len(key) < len(types.EntryPrefix)+8 {
			continue
		}
		epoch := binary.BigEndian.Uint64(key[len(types.EntryPrefix):])
		if epoch >= newOldest {
			// Keys sort in numeric order, so nothing below the horizon
			// remains once we reach it.
			break
		}
		stale = append(stale, append([]byte(nil), key...))
	}
	for _, key := range stale {
		store.Delete(key)
	}
	return len(stale)
}

// InitBounds sets both bounds directly, for genesis import.
//
// SetCommitment moves bounds as a side effect, but only upward: it raises the
// latest epoch and never lowers the retention horizon. That is what keeps an
// imported archive whose lower epochs were already pruned from reacquiring a
// horizon at its oldest surviving entry, which would turn time-barred
// evidence into an anomaly. The guard is in SetCommitment, not in the order
// these are called.
func (k Keeper) InitBounds(ctx sdk.Context, oldest, latest uint64) {
	k.setBounds(ctx, oldest, latest)
}

// IterateEntries walks every stored entry in key order.
func (k Keeper) IterateEntries(
	ctx sdk.Context,
	cb func(epoch uint64, seatRole uint32, entry types.ArchivedSeatCommitment) bool,
) error {
	store := ctx.KVStore(k.storeKey)
	it := storetypes.KVStorePrefixIterator(store, types.EntryPrefix)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		key := it.Key()
		if len(key) != len(types.EntryPrefix)+12 {
			return fmt.Errorf("malformed entry key of length %d", len(key))
		}
		epoch := binary.BigEndian.Uint64(key[len(types.EntryPrefix):])
		role := binary.BigEndian.Uint32(key[len(types.EntryPrefix)+8:])
		var entry types.ArchivedSeatCommitment
		if err := entry.Unmarshal(it.Value()); err != nil {
			return fmt.Errorf("entry (epoch %d, seat %d) does not decode: %w",
				epoch, role, err)
		}
		if !cb(epoch, role, entry) {
			return nil
		}
	}
	return nil
}
