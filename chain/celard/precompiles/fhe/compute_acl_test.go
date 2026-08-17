package fhe

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Compute operations must honour the frozen ABI's compute
// permission. These tests exist because the check was absent: the
// permission was defined, granted, and never consulted, which left
// the access-control list decorative.

var (
	hBal   = common.HexToHash("0xba1")
	hOther = common.HexToHash("0x0the")
)

// twoOperands packs two handles as an add(bytes32,bytes32) argument
// blob.
func twoOperands(a, b common.Hash) []byte {
	out := make([]byte, 0, 64)
	out = append(out, a.Bytes()...)
	out = append(out, b.Bytes()...)
	return out
}

func TestComputeAllowedForOwner(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	m := p.abi.Methods[AddMethod]
	p.registerHandle(db, hBal, ownerA, KTypeEuint64, false)
	p.registerHandle(db, hOther, ownerA, KTypeEuint64, false)

	err := p.checkComputeAccess(
		db, ownerA, &m, twoOperands(hBal, hOther), false)
	if err != nil {
		t.Fatalf("owner must be able to compute: %v", err)
	}
}

func TestComputeDeniedWithoutGrant(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	m := p.abi.Methods[AddMethod]
	p.registerHandle(db, hBal, ownerA, KTypeEuint64, false)
	p.registerHandle(db, hOther, ownerA, KTypeEuint64, false)

	wantErr(t, p.checkComputeAccess(
		db, strangerB, &m, twoOperands(hBal, hOther), false),
		"lacks compute permission")
}

func TestComputeAllowedAfterGrant(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	m := p.abi.Methods[AddMethod]
	p.registerHandle(db, hBal, ownerA, KTypeEuint64, false)
	p.registerHandle(db, hOther, ownerA, KTypeEuint64, false)
	p.grantPerm(db, hBal, strangerB, permBitCompute)
	p.grantPerm(db, hOther, strangerB, permBitCompute)

	err := p.checkComputeAccess(
		db, strangerB, &m, twoOperands(hBal, hOther), false)
	if err != nil {
		t.Fatalf("grantee must be able to compute: %v", err)
	}
}

func TestComputeRejectsUnknownOperand(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	m := p.abi.Methods[AddMethod]
	p.registerHandle(db, hBal, ownerA, KTypeEuint64, false)

	unknown := common.HexToHash("0xdead")
	wantErr(t, p.checkComputeAccess(
		db, ownerA, &m, twoOperands(hBal, unknown), false),
		"unknown handle")
}

func TestComputeSkippedInReadOnly(t *testing.T) {
	// A static call commits nothing and its handles are never
	// registered, so enforcing here would break simulation of
	// multi-step flows without protecting anything.
	p, db := mustPrecompile(t), newFakeStore()
	m := p.abi.Methods[AddMethod]

	err := p.checkComputeAccess(
		db, strangerB, &m, twoOperands(hBal, hOther), true)
	if err != nil {
		t.Fatalf("read-only must skip the check: %v", err)
	}
}

// TestBalanceProbeIsBlocked walks the disclosure route this check
// exists to close.
//
// Handles are public. Before the check existed, an observer could
// compute a predicate of somebody else's encrypted balance, own the
// result because results register to their creator, grant themselves
// reveal on it, and have the committee disclose the answer — about
// sixty-four queries recover a balance exactly. The route now fails
// at its first step.
func TestBalanceProbeIsBlocked(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()

	// a balance handle belonging to the token contract
	tokenContract := ownerA
	p.registerHandle(db, hBal, tokenContract, KTypeEuint64, false)

	// the observer's own public constant, which they legitimately own
	probe := common.HexToHash("0x64")
	p.registerHandle(db, probe, strangerB, KTypeEuint64, false)

	// step one: compare the two. This must fail.
	cmp := p.abi.Methods[LeMethod]
	wantErr(t, p.checkComputeAccess(
		db, strangerB, &cmp, twoOperands(hBal, probe), false),
		"lacks compute permission")

	// and owning one operand is not enough — the balance is still
	// not theirs to touch
	wantErr(t, p.checkComputeAccess(
		db, strangerB, &cmp, twoOperands(probe, hBal), false),
		"lacks compute permission")
}
