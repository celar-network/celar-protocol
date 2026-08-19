//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Slot layout mirrored from the precompile. The frozen ABI
// has no read method for the access list — that absence is
// deliberate and is why the token tracks provenance itself
// — so the only way to check a grant was actually issued
// is to read the precompile's storage.
const (
	baseSlotACL            = 2
	permBitReencryptToSelf = 0x02
)

var precompileAddr = common.HexToAddress(
	"0x0000000000000000000000000000000000000900")

// acl[h][grantee] = keccak256(pad32(grantee) ‖
//
//	keccak256(h ‖ uint256(2)))
func aclSlot(h common.Hash, grantee common.Address) common.Hash {
	var base common.Hash
	base[31] = baseSlotACL
	inner := crypto.Keccak256Hash(h.Bytes(), base.Bytes())
	var g common.Hash
	copy(g[12:], grantee.Bytes())
	return crypto.Keccak256Hash(g.Bytes(), inner.Bytes())
}

// A transfer claims to grant both parties the right to
// re-encrypt what actually moved, and to grant neither
// anything on the other's balance. Nothing checked that.
//
// The compute-permission defect of 2026-08-09 was exactly
// this shape: a permission the ABI defined, the contract
// relied on, and nothing enforced — invisible to tests
// because tests are written against the code that exists.
func TestTransferIssuesTheGrantsItClaims(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	granted := func(h common.Hash, who common.Address) bool {
		w := tk.db.GetState(precompileAddr, aclSlot(h, who))
		return w[31]&permBitReencryptToSelf != 0
	}

	// Model check first: mint grants the recipient the
	// right to read their own balance. If this fails the
	// slot derivation is wrong, not the contract — and
	// every assertion below would be vacuously true.
	ownerBal := tk.balanceOf(t, tk.owner)
	if !granted(ownerBal, tk.owner) {
		t.Fatalf("slot model wrong, or mint grants "+
			"nothing: acl[ownerBalance][owner] empty "+
			"(handle %x)", ownerBal)
	}

	var amount [32]byte
	copy(amount[:], ownerBal.Bytes())
	ret := tk.send(t, tk.owner,
		"confidentialTransfer", tk.other, amount)
	actual := unpackHandle(t, tk,
		"confidentialTransfer", ret)

	// Both parties may read what moved.
	if !granted(actual, tk.owner) {
		t.Error("sender was not granted re-encrypt on " +
			"the amount that moved")
	}
	if !granted(actual, tk.other) {
		t.Error("recipient was not granted re-encrypt " +
			"on the amount that moved")
	}

	// Neither learns the other's balance. This is the
	// half that matters: the grants above are a feature,
	// these are the confidentiality property.
	otherBal := tk.balanceOf(t, tk.other)
	newOwnerBal := tk.balanceOf(t, tk.owner)

	if w := tk.db.GetState(precompileAddr,
		aclSlot(otherBal, tk.owner)); w[31] != 0 {
		t.Errorf("sender holds bits %#x on the "+
			"recipient's balance handle", w[31])
	}
	if w := tk.db.GetState(precompileAddr,
		aclSlot(newOwnerBal, tk.other)); w[31] != 0 {
		t.Errorf("recipient holds bits %#x on the "+
			"sender's balance handle", w[31])
	}
}
