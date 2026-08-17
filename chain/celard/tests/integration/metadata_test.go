//go:build test

package integration

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The interface id must not be claimed while the operator
// model, confidentialTransferFrom and the AndCall family
// are absent — claiming it makes integrators call
// functions that do not exist.
func TestDoesNotClaimERC7984InterfaceId(t *testing.T) {
	tk := deployToken(t)

	check := func(id [4]byte) bool {
		ret := tk.send(t, tk.owner,
			"supportsInterface", id)
		out, err := tk.abi.Unpack(
			"supportsInterface", ret)
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		return out[0].(bool)
	}

	if check([4]byte{0x49, 0x58, 0xf2, 0xa4}) {
		t.Fatal("claims the ERC-7984 interface id while " +
			"its mandatory members are deliberately " +
			"absent")
	}
	if !check([4]byte{0x01, 0xff, 0xc9, 0xa7}) {
		t.Fatal("does not claim ERC-165, which it does " +
			"implement")
	}
}

// "Public by design" needs a mechanism, not a comment: the
// ACL has no wildcard, so nobody — not even the minter —
// could resolve the supply handle.
func TestTotalSupplyIsActuallyReadable(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	ret := tk.send(t, tk.owner, "totalSupplyPlain")
	out, err := tk.abi.Unpack("totalSupplyPlain", ret)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if got := out[0].(uint64); got != 100 {
		t.Fatalf("totalSupplyPlain = %d, want 100", got)
	}

	// The handle must be revealable, not merely returned.
	tk.send(t, tk.owner, "revealTotalSupply")
}

// A transfer to the zero address burns into a balance
// nobody can read while the supply still counts it.
func TestTransferToZeroIsRefused(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	bal := tk.balanceOf(t, tk.owner)
	var amount [32]byte
	copy(amount[:], bal.Bytes())

	err := tk.sendExpectingRevert(t, tk.owner,
		"confidentialTransfer",
		common.Address{}, amount)
	if err == nil {
		t.Fatal("transfer to the zero address was " +
			"accepted, burning into an unreadable " +
			"balance without reducing supply")
	}
	tk.refresh(t)

	// Control: the same transfer to a real account works.
	if err := tk.sendExpectingRevert(t, tk.owner,
		"confidentialTransfer", tk.other, amount,
	); err != nil {
		t.Fatalf("control failed: %v", err)
	}
}
