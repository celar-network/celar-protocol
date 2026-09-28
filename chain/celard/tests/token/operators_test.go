//go:build test

package token

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The operator model is time-boxed rather than an
// allowance. Every check in it is plaintext — caller,
// address, expiry — so refusing is permitted and leaks
// nothing.
func TestOperatorCanActWithinTheWindow(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	bal := tk.balanceOf(t, tk.owner)
	var amount [32]byte
	copy(amount[:], bal.Bytes())

	// Control first: not an operator yet, so refused.
	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransferFrom", tk.owner, tk.other, amount,
	); err == nil {
		t.Fatal("a non-operator moved the holder's tokens")
	}
	tk.refresh(t)

	// Grant, well into the future.
	until := big.NewInt(tk.ctx.BlockTime().Unix() + 3600)
	tk.send(t, tk.owner, "setOperator", tk.other, until)

	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransferFrom", tk.owner, tk.other, amount,
	); err != nil {
		t.Fatalf("the operator could not act within the window: %v", err)
	}
}

// Setting the expiry into the past is revocation — there is
// no separate call, and the same path is what an expiry
// crossing produces.
func TestExpiredGrantIsRefused(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	future := big.NewInt(tk.ctx.BlockTime().Unix() + 3600)
	tk.send(t, tk.owner, "setOperator", tk.other, future)

	bal := tk.balanceOf(t, tk.owner)
	var amount [32]byte
	copy(amount[:], bal.Bytes())

	// Control: it works while the grant is live.
	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransferFrom", tk.owner, tk.other, amount,
	); err != nil {
		t.Fatalf("control failed — operator could not act: %v", err)
	}

	// Revoke by setting the expiry behind us.
	past := big.NewInt(tk.ctx.BlockTime().Unix() - 1)
	tk.send(t, tk.owner, "setOperator", tk.other, past)

	bal2 := tk.balanceOf(t, tk.owner)
	var amount2 [32]byte
	copy(amount2[:], bal2.Bytes())

	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransferFrom", tk.owner, tk.other, amount2,
	); err == nil {
		t.Fatal("a revoked operator still moved the holder's tokens")
	}
	tk.refresh(t)
}

// The confused-deputy attack, arriving through delegation.
//
// Being someone's operator authorises moving THEIR tokens.
// It must not authorise naming a third party's balance
// handle as the amount: that would compute against the
// victim's balance and hand the operator a read grant on
// the result — the same attack the direct path already
// refuses, through a new door.
func TestOperatorCannotSpendAThirdPartysHandle(t *testing.T) {
	tk := deployToken(t)
	victim := common.HexToAddress(
		"0x00000000000000000000000000000000000000f1")

	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))
	tk.send(t, tk.owner, "mint", victim, uint64(500))

	until := big.NewInt(tk.ctx.BlockTime().Unix() + 3600)
	tk.send(t, tk.owner, "setOperator", tk.other, until)

	victimBal := tk.balanceOf(t, victim)
	var stolen [32]byte
	copy(stolen[:], victimBal.Bytes())

	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransferFrom", tk.owner, tk.other, stolen,
	); err == nil {
		t.Fatalf("operator named the victim's handle %x and was "+
			"allowed to compute against it", victimBal)
	}
	tk.refresh(t)

	// Control: the same operator can still move the
	// holder's own handle, so the refusal is about the
	// handle's provenance rather than the delegation.
	ownerBal := tk.balanceOf(t, tk.owner)
	var legit [32]byte
	copy(legit[:], ownerBal.Bytes())
	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransferFrom", tk.owner, tk.other, legit,
	); err != nil {
		t.Fatalf("control failed — operator could not move the "+
			"holder's own handle: %v", err)
	}
}
