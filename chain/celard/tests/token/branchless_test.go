//go:build test

package token

import (
	"testing"
)

// A transfer the sender cannot cover must not revert: it
// moves zero, chosen arithmetically. Reverting would
// publish the comparison — an observer learns whether the
// balance covered the amount from whether the transaction
// succeeded.
//
// What this can and cannot assert: the precompile derives
// handles and does not compute, so "amount exceeds
// balance" is not constructible here and the zero result
// is not observable. What IS observable is that the
// credited handle is exactly the select of the
// comparison — so the comparison feeds a select rather
// than a branch, and no balance-dependent revert path
// exists. Whether the arithmetic is correct is the
// coprocessor's business, not this layer's.
func TestTransferIsBranchlessAndNeverRevertsOnBalance(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	bal := tk.balanceOf(t, tk.owner)
	var amount [32]byte
	copy(amount[:], bal.Bytes())

	zero := deriveHandle("trivialEncrypt", trivialArgs(0))
	le := deriveHandle("le", words(bal, bal))
	actual := deriveHandle("select", words(le, bal, zero))
	credited := deriveHandle("add", words(zero, actual))

	logs := tk.sendCollectingLogs(t, tk.owner,
		"confidentialTransfer", tk.other, amount)

	if got := tk.balanceOf(t, tk.other); got != credited {
		t.Fatalf("recipient balance = %x, want %x — the "+
			"credit is not the select of the comparison, "+
			"so the transfer is not branchless",
			got, credited)
	}

	// Emitted whichever way the comparison went. Emitting
	// only on success would leak the predicate through the
	// presence of a log — the branchless rule applied to
	// logs rather than to control flow.
	if len(logs) == 0 {
		t.Fatal("no logs emitted; the transfer event " +
			"must fire unconditionally")
	}
}
