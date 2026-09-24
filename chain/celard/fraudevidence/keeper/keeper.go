package keeper

import (
	"bytes"

	"github.com/cosmos/evm/evmd/fraudevidence/types"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Keeper owns recorded convictions and coprocessor attestations.
//
// Native module rather than precompile storage, for the reason the commitment
// archive is one: this is consensus state written by chain logic and consumed
// by an off-chain verifier, not an operation on ciphertext.
//
// No codec, matching the archive: records marshal themselves under their
// canonical field numbers, and a codec here would be an unused dependency that
// later invites a second encoding path.
type Keeper struct {
	storeKey storetypes.StoreKey

	// The chain id bound into every attestation signature.
	//
	// Supplied at wiring time rather than read from config here: it is the
	// EVM chain id a coprocessor signs over, and taking it from the one place
	// that already knows it keeps this module independent of the EVM keeper.
	// A wrong value rejects every honest attestation, which is loud; a value
	// defaulted to zero would verify nothing, which is not.
	chainID uint64
}

func NewKeeper(storeKey storetypes.StoreKey, chainID uint64) Keeper {
	return Keeper{storeKey: storeKey, chainID: chainID}
}

// ChainID is the value attestation signatures are bound to.
func (k Keeper) ChainID() uint64 { return k.chainID }

// RecordVerdict stores a conviction, and reports whether it was already there.
//
// Idempotent on the SAME evidence and refusing on different evidence, which is
// the distinction that matters: resubmitting a proof someone has already acted
// on is ordinary - anyone may submit, so races are expected - while a second
// conviction of the same seat and epoch on DIFFERENT evidence is a separate
// fact that must not silently overwrite the first. Overwriting would erase the
// record a slash was already applied against.
func (k Keeper) RecordVerdict(ctx sdk.Context, v types.Verdict) (existed bool, err error) {
	key, err := types.VerdictKey(v.Epoch, v.SeatRole)
	if err != nil {
		return false, err
	}
	store := ctx.KVStore(k.storeKey)

	if bz := store.Get(key); bz != nil {
		var prior types.Verdict
		if err := prior.Unmarshal(bz); err != nil {
			return true, err
		}
		if prior.EvidenceSha256 != v.EvidenceSha256 {
			return true, types.ErrConflictingVerdict
		}
		// Same evidence, already recorded. Deliberately does NOT refresh
		// recorded_height or punished: the first record is when the chain
		// acted, and a later resubmission is not a new action.
		return true, nil
	}

	bz, err := v.Marshal()
	if err != nil {
		return false, err
	}
	store.Set(key, bz)
	return false, nil
}

// Verdict reports a recorded conviction and whether one exists.
func (k Keeper) Verdict(ctx sdk.Context, epoch uint64, seatRole uint32) (types.Verdict, bool, error) {
	key, err := types.VerdictKey(epoch, seatRole)
	if err != nil {
		return types.Verdict{}, false, err
	}
	bz := ctx.KVStore(k.storeKey).Get(key)
	if bz == nil {
		return types.Verdict{}, false, nil
	}
	var v types.Verdict
	if err := v.Unmarshal(bz); err != nil {
		return types.Verdict{}, true, err
	}
	return v, true, nil
}

// MarkPunished records that punishment has been applied.
//
// Separate from recording the verdict because the two happen at different
// times and, today, the second does not happen at all: the punishment hook
// waits on a decision this module does not own. Keeping the flag explicit is
// what stops a future hook running twice, and what makes "convicted but not
// punished" visible rather than indistinguishable from "handled".
func (k Keeper) MarkPunished(ctx sdk.Context, epoch uint64, seatRole uint32) error {
	v, found, err := k.Verdict(ctx, epoch, seatRole)
	if err != nil {
		return err
	}
	if !found {
		return types.ErrNoSuchVerdict
	}
	if v.Punished {
		return nil
	}
	v.Punished = true
	key, err := types.VerdictKey(epoch, seatRole)
	if err != nil {
		return err
	}
	bz, err := v.Marshal()
	if err != nil {
		return err
	}
	ctx.KVStore(k.storeKey).Set(key, bz)
	return nil
}


// RecordAttestation stores a coprocessor's attestation for one stream
// position, and reports whether one was already there.
//
// Same shape as recording a verdict, and for a related reason: a re-execution
// dispute is settled against what was attested, so silently replacing an
// attestation would change what a later challenge is comparing to. Identical
// resubmission is a no-op; a different attestation for the same position is a
// distinct claim and is refused here rather than overwritten.
//
// Two coprocessors disagreeing about one position is not an error in this
// module - it is the fraud game's entire subject. Refusing the write keeps
// the first claim intact and leaves the disagreement to the path that can
// adjudicate it.
func (k Keeper) RecordAttestation(ctx sdk.Context, a types.Attestation) (existed bool, err error) {
	key := types.AttestationKey(a.Height, a.TxIndex, a.LogIndex)
	store := ctx.KVStore(k.storeKey)

	if bz := store.Get(key); bz != nil {
		var prior types.Attestation
		if err := prior.Unmarshal(bz); err != nil {
			return true, err
		}
		if !bytes.Equal(prior.CtDigest, a.CtDigest) ||
			!bytes.Equal(prior.ResultHandle, a.ResultHandle) {
			return true, types.ErrConflictingAttestation
		}
		return true, nil
	}

	bz, err := a.Marshal()
	if err != nil {
		return false, err
	}
	store.Set(key, bz)
	return false, nil
}

// Attestation reports the attestation recorded for a stream position.
func (k Keeper) Attestation(ctx sdk.Context, height uint64, txIndex, logIndex uint32) (types.Attestation, bool, error) {
	bz := ctx.KVStore(k.storeKey).Get(types.AttestationKey(height, txIndex, logIndex))
	if bz == nil {
		return types.Attestation{}, false, nil
	}
	var a types.Attestation
	if err := a.Unmarshal(bz); err != nil {
		return types.Attestation{}, true, err
	}
	return a, true, nil
}
