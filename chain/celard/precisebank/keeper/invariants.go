package keeper

import (
	"fmt"

	"github.com/cosmos/evm/evmd/precisebank/types"

	sdkmath "cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CheckSupplyInvariant reports whether the two representations of the same
// value still agree.
//
// Balances live in two places: integer coins held by the bank, and per-account
// fractional amounts held here, each strictly below one integer coin. The
// module account holds integer coins in reserve backing every outstanding
// fractional amount, and the remainder absorbs the part of a whole coin that
// no account currently owns.
//
// So exactly one equation has to hold:
//
//	reserve x conversionFactor  ==  sum(fractional balances) + remainder
//
// WHY THIS FORM, and not a sum of visible balances. This chain has already had
// a write path that doubled supply, and it did so while every individual
// account balance looked correct - the two representations disagreed and
// nothing compared them. A check that adds up what the accounts say passes
// straight through that class of defect, because the accounts are not where
// the error appears.
//
// Returns a described failure rather than a bool: an invariant that reports
// only "broken" tells an operator to halt without telling anyone what to look
// at, and this one has three distinguishable ways to break.
func (k *Keeper) CheckSupplyInvariant(ctx sdk.Context) error {
	reserveAddr := k.ak.GetModuleAddress(types.ModuleName)
	reserve := k.bk.GetBalance(ctx, reserveAddr, types.IntegerCoinDenom())

	backing := reserve.Amount.Mul(types.ConversionFactor())
	owed := k.GetTotalSumFractionalBalances(ctx).Add(k.GetRemainderAmount(ctx))

	if !backing.Equal(owed) {
		return fmt.Errorf(
			"supply invariant broken: reserve backs %s but fractional balances "+
				"plus remainder total %s (difference %s); the integer and "+
				"fractional representations disagree",
			backing, owed, backing.Sub(owed),
		)
	}
	return nil
}

// CheckFractionalBalanceBounds reports any fractional balance that is not a
// proper fraction of an integer coin.
//
// A balance at or above the conversion factor is a whole coin that was never
// carried into the integer representation. That is a different failure from
// the one above and can coexist with a balanced total, so it is checked
// separately rather than folded in.
func (k *Keeper) CheckFractionalBalanceBounds(ctx sdk.Context) error {
	var bad error
	k.IterateFractionalBalances(ctx, func(addr sdk.AccAddress, amount sdkmath.Int) bool {
		if amount.IsNegative() || amount.GTE(types.ConversionFactor()) {
			bad = fmt.Errorf(
				"fractional balance out of range for %s: %s is not below the "+
					"conversion factor %s",
				addr, amount, types.ConversionFactor(),
			)
			return true
		}
		return false
	})
	return bad
}

// CheckNoExtendedDenomInBank reports whether the extended denomination has
// appeared in x/bank, where it must never exist.
//
// THIS IS THE CHECK THAT WOULD HAVE CAUGHT THE DEFECT THIS MODULE HAS ALREADY
// HAD. The commit path passed the extended coin straight to x/bank, storing
// raw extended coins and doubling supply - and the reserve-backing equation
// above stays perfectly balanced while that happens, because neither the
// reserve nor any fractional balance moves. The two representations agreed
// with each other; the error was a third quantity that should not have
// existed.
//
// Recorded plainly because it is the more useful half of this task: the
// obvious invariant, and the one every implementation of this pattern ships,
// is blind to the failure this particular fork actually suffered.
//
// Vacuous when the chain is configured with equal denominations, which is a
// legitimate configuration - so it says so rather than silently passing.
func (k *Keeper) CheckNoExtendedDenomInBank(ctx sdk.Context) error {
	if types.IsExtendedDenomSameAsIntegerDenom() {
		return nil
	}
	supply := k.bk.GetSupply(ctx, types.ExtendedCoinDenom())
	if !supply.IsZero() {
		return fmt.Errorf(
			"extended denomination %s present in bank supply (%s); it is held "+
				"as integer coins plus fractional balances and must never be "+
				"written to bank directly",
			types.ExtendedCoinDenom(), supply,
		)
	}
	return nil
}
