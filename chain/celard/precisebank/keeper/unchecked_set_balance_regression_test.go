package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/evm/evmd/precisebank/types"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

// TestUncheckedSetBalance_SplitsExtendedDenom is the regression test for the
// precisebank write-path bug: the EVM commit path
// (statedb.SetBalance -> BankWrapper.SetBalance -> UncheckedSetBalance) used to
// pass the extended (18-dec) coin straight to x/bank, storing raw extended coins
// and doubling supply. The fix must split the target into an integer bank balance
// plus a fractional store balance, and must NEVER write the extended denom to x/bank.
func TestUncheckedSetBalance_SplitsExtendedDenom(t *testing.T) {
	td := newMockedTestData(t)

	addr := sdk.AccAddress([]byte("regression-test-acct")) // 20 bytes
	reserve := sdk.AccAddress([]byte("precisebank-reserve!")) // 20 bytes

	cf := types.ConversionFactor()
	// Target extended balance = 3 integer units + 250 fractional units.
	target := cf.MulRaw(3).Add(sdkmath.NewInt(250))

	td.ak.On("GetModuleAddress", types.ModuleName).Return(reserve)

	// Core guarantee: x/bank is asked to store the INTEGER denom (amount 3),
	// never the extended denom.
	td.bk.On("UncheckedSetBalance", mock.Anything, addr,
		ci(types.IntegerCoinDenom(), sdkmath.NewInt(3))).Return(nil).Once()
	// Fractional went 0 -> 250 with remainder 0, so exactly one reserve coin is minted.
	td.bk.On("MintCoins", mock.Anything, types.ModuleName,
		cs(ci(types.IntegerCoinDenom(), sdkmath.OneInt()))).Return(nil).Once()

	err := td.keeper.UncheckedSetBalance(td.ctx, addr, ci(types.ExtendedCoinDenom(), target))
	require.NoError(t, err)

	// Fractional part is stored in x/precisebank, not x/bank.
	require.Equal(t, sdkmath.NewInt(250), td.keeper.GetFractionalBalance(td.ctx, addr))

	// Round-trip: GetBalance recombines integer*CF + fractional == target.
	td.bk.On("GetBalance", mock.Anything, addr, types.IntegerCoinDenom()).
		Return(ci(types.IntegerCoinDenom(), sdkmath.NewInt(3)))
	got := td.keeper.GetBalance(td.ctx, addr, types.ExtendedCoinDenom())
	require.Equal(t, ci(types.ExtendedCoinDenom(), target), got)
}
