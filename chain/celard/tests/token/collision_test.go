//go:build test

package token

import (
	"testing"
)

// Two accounts minted the same amount no longer share a balance handle.
//
// They used to. A handle named a computation trace and nothing else, so
// add(Z, 100) was the same handle whoever computed it, and the two accounts
// arrived at identical bytes by doing an ordinary thing — no attacker
// involved. This test asserted that collision and pinned the claimant-set
// provenance that made it survivable.
//
// The state-entry op now binds the calling contract and the account, so each
// account's encrypted zero is its own and everything built on it diverges.
// The test is inverted rather than deleted: it is the record that the
// collision was demonstrated before it was closed, and it is the guard that
// would fail first if the principal ever stopped reaching the derivation.
//
// What this does NOT claim: that equal balances are indistinguishable in
// general. It claims the specific trace that produced identical handles no
// longer does. Two accounts whose balances were reached by identical traces
// from the same principal would still collide, which is a property of the
// compute ops and out of scope here.
func TestTwoAccountsMintedTheSameAmountDoNotCollide(t *testing.T) {
	tk := deployToken(t)

	// other is minted first, owner second — same amount.
	tk.send(t, tk.owner, "mint", tk.other, uint64(100))
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	a := tk.balanceOf(t, tk.other)
	b := tk.balanceOf(t, tk.owner)
	if a == b {
		t.Fatalf("two accounts minted the same amount share a balance "+
			"handle (%x): the principal is not reaching the state-entry "+
			"derivation, and anyone reading the two storage slots learns "+
			"the balances are equal without decrypting anything", a)
	}

	// Each spends its own, and neither can spend the other's — the claimant
	// record is what enforces that, and it outlives the collision it was
	// introduced for.
	var amtA [32]byte
	copy(amtA[:], a.Bytes())
	tk.send(t, tk.other, "confidentialTransfer", tk.owner, amtA)

	if err := tk.sendExpectingRevert(t, tk.owner,
		"confidentialTransfer", tk.other, amtA); err == nil {
		t.Fatal("an account spent a handle issued to somebody else: with " +
			"handles no longer shared, this is the confused deputy rather " +
			"than an honest collision")
	}
	tk.refresh(t)

	if got := tk.balanceOf(t, tk.other); got == a {
		t.Fatalf("first holder's balance unchanged after spending: %x", got)
	}
}
