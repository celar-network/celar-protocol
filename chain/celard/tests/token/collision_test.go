package token

import (
	"testing"
)

// Handles name a computation trace, not an account. Two accounts minted
// the same amount therefore share a balance handle — add(Z, 100) is the
// same handle whoever computes it — and no attacker is involved: the
// collision is reachable by two honest users doing an ordinary thing.
//
// Under first-writer-wins provenance the second holder was locked out of
// its own balance. Provenance is now a claimant SET, and this test pins
// that both holders can spend.
//
// Whether a shared handle denotes one underlying balance or two is NOT
// answerable at this layer: _balances is keyed per account, sub(H100, 40)
// yields H60 whether or not anyone else did the same, and nothing reverts
// in either world. It is answered by decryption in
// fhe/backend-adapter/zama/tests/collision.rs — two balances; the shared
// operand is never mutated, and 60+60+40+40 closes against the 200 minted.
func TestTwoAccountsMintedTheSameAmount(t *testing.T) {
	tk := deployToken(t)

	// other is minted first, owner second — same amount.
	tk.send(t, tk.owner, "mint", tk.other, uint64(100))
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	a := tk.balanceOf(t, tk.other)
	b := tk.balanceOf(t, tk.owner)
	if a != b {
		t.Fatalf("expected a shared handle, got %x vs %x", a, b)
	}

	var amt [32]byte
	copy(amt[:], a.Bytes())

	// The first holder spends the shared handle.
	tk.send(t, tk.other, "confidentialTransfer", tk.owner, amt)

	// The second holder spends the SAME handle. This is the regression:
	// it reverted under first-writer-wins, because the handle had been
	// bound to whichever account minted first.
	tk.send(t, tk.owner, "confidentialTransfer", tk.other, amt)

	// Value moved on both spends — neither account is left holding the
	// handle it started with.
	if got := tk.balanceOf(t, tk.other); got == a {
		t.Fatalf("first holder's balance unchanged after spending: %x", got)
	}
	if got := tk.balanceOf(t, tk.owner); got == a {
		t.Fatalf("second holder's balance unchanged after spending: %x", got)
	}
}
