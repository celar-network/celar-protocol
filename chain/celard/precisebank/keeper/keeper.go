package keeper

import (
	"context"

	"github.com/cosmos/evm/evmd/precisebank/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	sdkmath "cosmossdk.io/math"

	"github.com/cosmos/cosmos-sdk/codec"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Enforce that Keeper implements the expected keeper interfaces
var _ evmtypes.BankKeeper = Keeper{}

// Keeper defines the precisebank module's keeper
type Keeper struct {
	cdc      codec.BinaryCodec
	storeKey storetypes.StoreKey

	bk types.BankKeeper
	ak types.AccountKeeper
}

// NewKeeper creates a new keeper
func NewKeeper(
	cdc codec.BinaryCodec,
	storeKey storetypes.StoreKey,
	bk types.BankKeeper,
	ak types.AccountKeeper,
) Keeper {
	return Keeper{
		cdc:      cdc,
		storeKey: storeKey,
		bk:       bk,
		ak:       ak,
	}
}

// BANK KEEPER INTERFACE PASSTHROUGHS
func (k Keeper) SendCoinsFromModuleToAccountVirtual(ctx context.Context, senderModule string, recipientAddr sdk.AccAddress, amt sdk.Coins) error {
	return k.bk.SendCoinsFromModuleToAccountVirtual(ctx, senderModule, recipientAddr, amt)
}

func (k Keeper) SendCoinsFromAccountToModuleVirtual(ctx context.Context, senderAddr sdk.AccAddress, recipientModule string, amt sdk.Coins) error {
	return k.bk.SendCoinsFromAccountToModuleVirtual(ctx, senderAddr, recipientModule, amt)
}

// UncheckedSetBalance sets an account's absolute balance. For the extended denom
// (18-dec acelar) it splits the target into an integer ncelar balance (stored in
// x/bank) plus a sub-unit fractional balance (stored in x/precisebank), mirroring
// GetBalance's read (integer*CF + fractional), and reconciles the reserve for the
// change in this account's fractional balance. Other denoms pass through to x/bank.
//
// Without this split, EVM balance writes (statedb.SetBalance -> BankWrapper ->
// UncheckedSetBalance) would store raw acelar bank coins alongside the untouched
// ncelar, double-counting supply.
func (k Keeper) UncheckedSetBalance(ctx context.Context, addr sdk.AccAddress, amt sdk.Coin) error {
	// Non-extended denoms pass straight through to x/bank.
	if amt.Denom != types.ExtendedCoinDenom() {
		return k.bk.UncheckedSetBalance(ctx, addr, amt)
	}

	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// The reserve (precisebank module account) only ever holds integer coins that
	// back fractional balances; never assign it a fractional balance.
	if addr.Equals(k.ak.GetModuleAddress(types.ModuleName)) {
		integer := amt.Amount.Quo(types.ConversionFactor())
		return k.bk.UncheckedSetBalance(ctx, addr, sdk.NewCoin(types.IntegerCoinDenom(), integer))
	}

	newInteger := amt.Amount.Quo(types.ConversionFactor())
	newFractional := amt.Amount.Mod(types.ConversionFactor())
	oldFractional := k.GetFractionalBalance(sdkCtx, addr)

	// 1) set the integer (ncelar) balance directly in x/bank.
	if err := k.bk.UncheckedSetBalance(ctx, addr, sdk.NewCoin(types.IntegerCoinDenom(), newInteger)); err != nil {
		return err
	}

	// 2) reconcile the reserve for the change in this account's fractional balance.
	// Reserve invariant: reserveInteger*CF = sum(fractional) + remainder, 0<=remainder<CF.
	// Changing this account's fractional by delta shifts sum(fractional) by delta; keep
	// remainder in [0,CF) by minting/burning at most one reserve integer coin.
	delta := newFractional.Sub(oldFractional)
	if !delta.IsZero() {
		newRemainder := k.GetRemainderAmount(sdkCtx).Sub(delta)
		switch {
		case newRemainder.IsNegative():
			// Fractional in circulation grew past the remainder's backing: mint 1 reserve coin.
			if err := k.bk.MintCoins(ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin(types.IntegerCoinDenom(), sdkmath.OneInt()))); err != nil {
				return err
			}
			newRemainder = newRemainder.Add(types.ConversionFactor())
		case newRemainder.GTE(types.ConversionFactor()):
			// Fractional in circulation shrank: burn 1 reserve coin.
			if err := k.bk.BurnCoins(ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin(types.IntegerCoinDenom(), sdkmath.OneInt()))); err != nil {
				return err
			}
			newRemainder = newRemainder.Sub(types.ConversionFactor())
		}
		k.SetRemainderAmount(sdkCtx, newRemainder)
	}

	// 3) set the account's fractional balance.
	k.SetFractionalBalance(sdkCtx, addr, newFractional)
	return nil
}

func (k Keeper) IterateTotalSupply(ctx context.Context, cb func(coin sdk.Coin) bool) {
	k.bk.IterateTotalSupply(ctx, cb)
}

// GetSupply returns the supply of a denom. For the extended denom it returns the
// virtual supply derived from the integer supply and the outstanding remainder:
// extendedSupply = integerSupply*CF - remainder. Other denoms pass through.
func (k Keeper) GetSupply(ctx context.Context, denom string) sdk.Coin {
	if denom != types.ExtendedCoinDenom() {
		return k.bk.GetSupply(ctx, denom)
	}
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	integerSupply := k.bk.GetSupply(ctx, types.IntegerCoinDenom()).Amount
	remainder := k.GetRemainderAmount(sdkCtx)
	extended := integerSupply.Mul(types.ConversionFactor()).Sub(remainder)
	return sdk.NewCoin(types.ExtendedCoinDenom(), extended)
}

func (k Keeper) LockedCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins {
	return k.bk.LockedCoins(ctx, addr)
}
