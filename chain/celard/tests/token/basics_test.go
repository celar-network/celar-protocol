//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestMetadata(t *testing.T) {
	tk := deployToken(t)

	str := func(method string) string {
		out, err := tk.abi.Unpack(method,
			tk.send(t, tk.owner, method))
		if err != nil {
			t.Fatalf("unpack %s: %v", method, err)
		}
		return out[0].(string)
	}

	if got := str("name"); got != "Celar Test" {
		t.Errorf("name = %q", got)
	}
	if got := str("symbol"); got != "CELT" {
		t.Errorf("symbol = %q", got)
	}
	if got := str("contractURI"); got == "" {
		t.Error("contractURI is empty; the standard " +
			"requires it")
	}

	out, err := tk.abi.Unpack("decimals",
		tk.send(t, tk.owner, "decimals"))
	if err != nil {
		t.Fatalf("unpack decimals: %v", err)
	}
	// Six is the token's display scale and is unrelated
	// to the chain's nine-decimal native coin. Conflating
	// the two is the oldest trap in this project.
	if got := out[0].(uint8); got != 6 {
		t.Errorf("decimals = %d, want 6", got)
	}
}

// Minting is the one privileged operation. A plaintext
// check on the caller, so refusing is allowed — nothing
// encrypted is involved.
func TestOnlyMinterCanMint(t *testing.T) {
	tk := deployToken(t)

	if err := tk.sendExpectingRevert(t, tk.other,
		"mint", tk.other, uint64(1_000_000),
	); err == nil {
		t.Fatal("a non-minter minted tokens")
	}
	tk.refresh(t)

	// Control: the minter still can, so the refusal above
	// is about authority rather than about that account
	// being unable to transact.
	if err := tk.sendExpectingRevert(t, tk.owner,
		"mint", tk.owner, uint64(100),
	); err != nil {
		t.Fatalf("the minter could not mint: %v", err)
	}
}

// Balances must stay separate handles per account, and
// provenance must survive a second hop. Both are
// properties the single-account tests cannot see: with one
// holder, a bookkeeping error that collapses two accounts
// onto one handle looks identical to correct behaviour.
func TestTwoAccountsKeepSeparateBalances(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))
	tk.send(t, tk.owner, "mint", tk.other, uint64(50))

	ownerBal := tk.balanceOf(t, tk.owner)
	otherBal := tk.balanceOf(t, tk.other)
	if ownerBal == otherBal {
		t.Fatalf("both accounts share balance handle %x "+
			"— separate holders must not collapse onto "+
			"one handle", ownerBal)
	}
	if ownerBal == (common.Hash{}) ||
		otherBal == (common.Hash{}) {
		t.Fatal("a minted account still has the zero " +
			"handle, meaning no balance was recorded")
	}

	// Owner sends to other; other forwards what arrived to
	// a third party. The second hop is where provenance
	// recorded against the wrong party would trap value.
	var amount [32]byte
	copy(amount[:], ownerBal.Bytes())
	ret := tk.send(t, tk.owner,
		"confidentialTransfer", tk.other, amount)
	actual := unpackHandle(t, tk,
		"confidentialTransfer", ret)

	third := common.HexToAddress(
		"0x00000000000000000000000000000000000000ff")
	var onward [32]byte
	copy(onward[:], actual.Bytes())
	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransfer", third, onward,
	); err != nil {
		t.Fatalf("recipient could not forward what they "+
			"received: %v", err)
	}

	// And the two original holders still differ.
	if tk.balanceOf(t, tk.owner) == tk.balanceOf(t, tk.other) {
		t.Error("balances converged to one handle after " +
			"transfers")
	}
}
