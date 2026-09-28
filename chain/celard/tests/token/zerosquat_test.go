//go:build test

package token

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The shared encrypted zero, and why it is no longer squattable.
//
// It used to be. TFHE.asEuint64(0) derived one handle for every caller on the
// chain, trivialEncrypt skips the compute-access check because it takes no
// handle operands, and registration is first-writer-wins with no revocation.
// So any account could register that handle to itself for the price of one
// call, after which a contract needing an encrypted zero could not grant on it
// and re-derived the same foreign-owned handle forever: deployment, or every
// mint and transfer, failed permanently. It was found by accident — a probe in
// this suite called trivialEncrypt from an EOA and the next deployment broke.
//
// The state-entry op now takes the account as a required argument and derives
// from the CALLER and that account. Both halves matter and each alone fails:
// with only the caller, every user of one contract still collides; with only
// the account, an outsider names someone else's account and squats it anyway.
//
// This file is the inversion of the test that demonstrated the exposure. It
// keeps the attack rather than deleting it, and asserts that it now fails.
func TestSharedZeroIsNoLongerSquattable(t *testing.T) {
	tk := deployToken(t)

	// The victim account has NO balance yet, so the contract has not derived
	// its zero. That is the only moment the squat was ever reachable: once a
	// balance exists, _ensure never re-derives and the attack has nothing to
	// take.
	//
	// Asserted through the token's BEHAVIOUR rather than by comparing the
	// squatter's handle against one this test predicts. A predicted handle
	// shares a formula with the chain, so dropping a field from both sides
	// keeps the comparison true and the test green — which is exactly what
	// happened to the first version of this test under mutation.
	sel := crypto.Keccak256(
		[]byte("trivialEncrypt(uint64,uint8,address)"))[:4]
	data := append([]byte{}, sel...)
	data = append(data, common.LeftPadBytes(big.NewInt(0).Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(big.NewInt(64).Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(tk.other.Bytes(), 32)...)

	pre := common.HexToAddress(
		"0x0000000000000000000000000000000000000900")
	res, err := tk.k.CallEVMWithData(
		tk.ctx, tk.db, tk.owner, &pre, data,
		true, false, big.NewInt(5_000_000))
	if err != nil {
		t.Fatalf("squat probe: %v", err)
	}
	t.Logf("squatter registered %x naming %s as principal",
		common.BytesToHash(res.Ret), tk.other.Hex())

	// The token must still be able to give that account a balance. If the
	// squatter's call reached the handle this contract derives for that
	// account, _ensure now re-derives a foreign-owned handle, the grant
	// fails, and this mint reverts — which is the original defect exactly.
	tk.send(t, tk.owner, "mint", tk.other, uint64(100))

	if got := tk.balanceOf(t, tk.other); got == (common.Hash{}) {
		t.Fatal("the account has no balance after a successful mint")
	}
}

// A blank principal would make the separator optional in practice: every
// account of one contract could pass it, and the intra-contract collision the
// argument exists to close would come straight back. Required means refused,
// not defaulted.
func TestZeroPrincipalIsRefused(t *testing.T) {
	tk := deployToken(t)

	sel := crypto.Keccak256(
		[]byte("trivialEncrypt(uint64,uint8,address)"))[:4]
	data := append([]byte{}, sel...)
	data = append(data, common.LeftPadBytes(big.NewInt(0).Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(big.NewInt(64).Bytes(), 32)...)
	data = append(data, make([]byte, 32)...)

	pre := common.HexToAddress(
		"0x0000000000000000000000000000000000000900")
	if _, err := tk.k.CallEVMWithData(
		tk.ctx, tk.db, tk.other, &pre, data,
		true, false, big.NewInt(5_000_000),
	); err == nil {
		t.Fatal("a zero principal was accepted: the separator is optional " +
			"in practice, whatever the signature says")
	}
}
