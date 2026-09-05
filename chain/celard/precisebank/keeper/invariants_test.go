package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/evm/evmd/precisebank/types"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// A balanced ledger: the reserve holds exactly the integer coins that back the
// outstanding fractional balances.
func TestSupplyInvariantHoldsWhenTheReserveBacksTheFractions(t *testing.T) {
	td := newMockedTestData(t)
	reserve := sdk.AccAddress([]byte("precisebank-reserve!"))
	addr := sdk.AccAddress([]byte("holder--------------"))
	cf := types.ConversionFactor()

	td.keeper.SetFractionalBalance(td.ctx, addr, cf.QuoRaw(4))
	td.keeper.SetRemainderAmount(td.ctx, cf.Sub(cf.QuoRaw(4)))

	td.ak.EXPECT().GetModuleAddress(types.ModuleName).Return(reserve)
	td.bk.EXPECT().
		GetBalance(td.ctx, reserve, types.IntegerCoinDenom()).
		Return(sdk.NewCoin(types.IntegerCoinDenom(), sdkmath.NewInt(1)))

	require.NoError(t, td.keeper.CheckSupplyInvariant(td.ctx))
}

// The reserve no longer covers what is owed: one integer coin backing two
// coins' worth of fractional balances.
func TestSupplyInvariantCatchesAnUnderBackedReserve(t *testing.T) {
	td := newMockedTestData(t)
	reserve := sdk.AccAddress([]byte("precisebank-reserve!"))
	addr := sdk.AccAddress([]byte("holder--------------"))
	cf := types.ConversionFactor()

	// Two accounts, each holding half a coin. Individually valid - a
	// fractional balance is always below one coin - but together they owe a
	// whole coin the reserve does not hold.
	//
	// The remainder cannot be used to construct this: it is capped below one
	// conversion factor and its setter panics above that, so an over-large
	// remainder is not a reachable state. Testing against one would have been
	// testing a fiction, which is what the first version of this test did.
	other := sdk.AccAddress([]byte("holder-two----------"))
	td.keeper.SetFractionalBalance(td.ctx, addr, cf.QuoRaw(2))
	td.keeper.SetFractionalBalance(td.ctx, other, cf.QuoRaw(2))
	td.keeper.SetRemainderAmount(td.ctx, sdkmath.ZeroInt())

	td.ak.EXPECT().GetModuleAddress(types.ModuleName).Return(reserve)
	td.bk.EXPECT().
		GetBalance(td.ctx, reserve, types.IntegerCoinDenom()).
		Return(sdk.NewCoin(types.IntegerCoinDenom(), sdkmath.ZeroInt()))

	err := td.keeper.CheckSupplyInvariant(td.ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "representations disagree")
}

// THE ONE THAT MATTERS.
//
// This reconstructs the state the original defect produced: extended coins
// written straight into bank, while the reserve and the fractional balances
// remain perfectly consistent with each other.
//
// The reserve-backing invariant PASSES on that state. It is the invariant this
// pattern normally ships, and it is blind to the failure this module actually
// had, because the error is a third quantity rather than a disagreement
// between the two it compares.
func TestTheReserveInvariantIsBlindToExtendedCoinsInBank(t *testing.T) {
	td := newMockedTestData(t)
	reserve := sdk.AccAddress([]byte("precisebank-reserve!"))
	cf := types.ConversionFactor()

	// Reserve and fractions agree: nothing outstanding, nothing backed.
	td.keeper.SetRemainderAmount(td.ctx, sdkmath.ZeroInt())
	td.ak.EXPECT().GetModuleAddress(types.ModuleName).Return(reserve)
	td.bk.EXPECT().
		GetBalance(td.ctx, reserve, types.IntegerCoinDenom()).
		Return(sdk.NewCoin(types.IntegerCoinDenom(), sdkmath.ZeroInt()))

	require.NoError(t, td.keeper.CheckSupplyInvariant(td.ctx),
		"precondition: the two representations agree, so the standard "+
			"invariant must pass - that is the point of this test")

	// And yet extended coins exist in bank, which is the defect.
	td.bk.EXPECT().
		GetSupply(td.ctx, types.ExtendedCoinDenom()).
		Return(sdk.NewCoin(types.ExtendedCoinDenom(), cf.MulRaw(3)))

	err := td.keeper.CheckNoExtendedDenomInBank(td.ctx)
	require.Error(t, err, "extended coins in bank must be caught by something")
	require.Contains(t, err.Error(), "must never be written to bank directly")
}

// A fractional balance at or above one whole coin is a carry that never
// happened. It can coexist with a balanced total, so it is checked separately.
func TestFractionalBalanceBoundsAreChecked(t *testing.T) {
	td := newMockedTestData(t)
	addr := sdk.AccAddress([]byte("holder--------------"))
	td.keeper.SetFractionalBalance(td.ctx, addr, types.ConversionFactor().SubRaw(1))
	require.NoError(t, td.keeper.CheckFractionalBalanceBounds(td.ctx))
}
