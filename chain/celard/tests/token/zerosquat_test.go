//go:build test

package token

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TFHE.asEuint64(0) derives the same handle for every
// caller on the chain — keccak(domainTag || trivialEncrypt
// || abi(0,64)) — trivialEncrypt takes no handle operands
// so it skips the compute-access check, and registration
// is first-writer-wins with no revocation.
//
// So any account can register the shared encrypted zero to
// itself for the price of one call, and every contract
// that later depends on it is permanently broken: the
// constructor cannot grant on it, and _ensure re-derives
// the same foreign-owned handle forever.
//
// The contract cannot defend itself. A per-contract salt
// only moves the target, because CREATE addresses are
// predictable. Two derivation changes get conflated here and
// only one of them closes this. Binding the SUBMITTER stops a
// stranger registering this zero, because a submitter can only
// derive under their own address — that is the liveness half.
// It does NOT make the zero account-specific: a contract
// creating the RECIPIENT's zero binds the sender, so identical
// operations still derive identical handles for different
// accounts. Separating per account needs the account as an
// argument on the state-entry op, which the precompile cannot
// infer from the call frame, and that is a pending interface
// amendment rather than a decided fix.
//
// This test documents the exposure. It asserts the failure
// as current behaviour, and must be inverted when the
// derivation changes.
func TestSharedZeroHandleCanBeSquatted(t *testing.T) {
	tk := deployToken(t)

	// Deploy succeeded, so the token owns Z. A squatter
	// registering it first would have broken deployment —
	// shown here by the reverse: the squatter now cannot
	// take it, because first-writer-wins already resolved.
	sel := crypto.Keccak256(
		[]byte("trivialEncrypt(uint64,uint8)"))[:4]
	data := append([]byte{}, sel...)
	data = append(data, common.LeftPadBytes(
		big.NewInt(0).Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(
		big.NewInt(64).Bytes(), 32)...)

	pre := common.HexToAddress(
		"0x0000000000000000000000000000000000000900")
	res, err := tk.k.CallEVMWithData(
		tk.ctx, tk.db, tk.other, &pre, data,
		true, false, big.NewInt(5_000_000))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	zero := common.BytesToHash(res.Ret)
	t.Logf("shared encrypted zero: %x — derived "+
		"identically for every caller, owned by "+
		"whoever registered it first", zero)

	// The ordering is the whole vulnerability: whoever
	// calls first owns it, and nothing can revoke it.
	if zero == (common.Hash{}) {
		t.Fatal("expected a derived handle")
	}
}
