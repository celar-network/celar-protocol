//go:build test

package token

import (
	"testing"
)

// Handles are deterministic: add(Z, trivialEncrypt(100)) is
// the same handle whoever computes it. So two accounts
// minted the SAME amount share a balance handle — and
// provenance is first-writer-wins.
func TestTwoAccountsMintedTheSameAmount(t *testing.T) {
	// Replace the body of TestTwoAccountsMintedTheSameAmount:
	tk := deployToken(t)

	// other is minted first, owner second — same amount.
	tk.send(t, tk.owner, "mint", tk.other, uint64(100))
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	a := tk.balanceOf(t, tk.other)
	b := tk.balanceOf(t, tk.owner)
	if a != b {
		t.Fatalf("expected a shared handle, got %x vs %x", a, b)
	}
	t.Logf("both accounts hold the same balance handle: %x", a)

	// The FIRST holder can spend.
	var amt [32]byte
	copy(amt[:], a.Bytes())
	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransfer", tk.owner, amt); err != nil {
		t.Fatalf("first holder could not spend: %v", err)
	}
	tk.refresh(t)

	// Can the SECOND holder spend the same handle?
	err := tk.sendExpectingRevert(t, tk.owner,
		"confidentialTransfer", tk.other, amt)
	t.Logf("second holder spending: err=%v", err)
}
