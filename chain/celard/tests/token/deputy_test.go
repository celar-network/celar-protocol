//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The precompile authorizes the *caller*, which for any
// contract call is the token contract — and the token owns
// every balance handle it created. So the ACL check that
// stops a stranger operating on someone else's balance
// passes when the token does it on their behalf.
//
// Balance handles are public via confidentialBalanceOf, so
// an attacker names the victim's handle as the amount:
//
//	ok     = le(victimBal, attackerBal)
//	actual = select(ok, victimBal, 0)
//	grant  reencrypt-to-self on actual, to the attacker
//
// If the attacker's balance covers the victim's, `actual`
// carries the victim's balance and they decrypt it exactly,
// in one transaction, at no cost since they own both ends.
// Otherwise they still learn victimBal > attackerBal.
//
// This is TestBalanceProbeIsBlocked routed through a
// contract the precompile trusts.
func TestCannotTransferAHandleYouWereNotIssued(t *testing.T) {
	tk := deployToken(t)

	// Victim holds a balance.
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))
	victimBal := tk.balanceOf(t, tk.owner)

	// Attacker funds themselves so the comparison can
	// succeed, then names the victim's handle as the
	// amount, sending to an account they control.
	tk.send(t, tk.owner, "mint", tk.other, uint64(1000))

	var amount [32]byte
	copy(amount[:], victimBal.Bytes())

	err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransfer", tk.other, amount)
	if err == nil {
		t.Fatalf("the token operated on a handle the "+
			"caller was never issued: an attacker can "+
			"name the victim's balance handle %x as the "+
			"transfer amount and be granted "+
			"reencrypt-to-self on the result",
			victimBal)
	}
	t.Logf("refused, as required: %v", err)

	tk.refresh(t)

	// Control: the same caller, transferring a handle that
	// WAS issued to them, must succeed — otherwise the
	// refusal above proves only that this account cannot
	// transact, not that provenance is being enforced.
	ownBal := tk.balanceOf(t, tk.other)
	var own [32]byte
	copy(own[:], ownBal.Bytes())

	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransfer", tk.owner, own,
	); err != nil {
		t.Fatalf("control failed — the caller cannot "+
			"transfer even their own issued handle, so "+
			"the refusal above proves nothing: %v", err)
	}

	_ = common.Hash{}
}
