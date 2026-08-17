//go:build test

package integration

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The precompile is a stub: it derives handles and never
// computes values, so no test at this layer can observe
// "the balance doubled". What is observable is the handle
// DAG, which is fully deterministic —
// keccak256(domainTag || method || rawArgs).
//
// With the aliasing bug the stored balance is
// add(balance, actual): both operands are read before
// either write, so for a self-transfer the credit
// overwrites the debit and the sub result is discarded.
// Correct, it is add(sub(balance, actual), actual).
//
// The test validates its own model against the balance
// after mint before asserting anything, so a mismatch says
// whether the contract or the model is wrong.

const fheDomainTag = "celar.fhe.v0"

func deriveHandle(method string, args []byte) common.Hash {
	p := append([]byte(fheDomainTag), []byte(method)...)
	return crypto.Keccak256Hash(append(p, args...))
}

func words(hs ...common.Hash) []byte {
	out := make([]byte, 0, 32*len(hs))
	for _, h := range hs {
		out = append(out, h.Bytes()...)
	}
	return out
}

func trivialArgs(v uint64) []byte {
	out := common.LeftPadBytes(
		new(big.Int).SetUint64(v).Bytes(), 32)
	return append(out, common.LeftPadBytes(
		big.NewInt(64).Bytes(), 32)...)
}

func TestSelfTransferDoesNotMint(t *testing.T) {
	tk := deployToken(t)

	zero := deriveHandle("trivialEncrypt", trivialArgs(0))
	minted := deriveHandle("trivialEncrypt", trivialArgs(100))
	afterMint := deriveHandle("add", words(zero, minted))

	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	got := tk.balanceOf(t, tk.owner)
	if got != afterMint {
		t.Fatalf("the derivation model is wrong, not the "+
			"contract:\n balance after mint = %x\n "+
			"model predicted    = %x", got, afterMint)
	}

	// Self-transfer of the entire balance.
	le := deriveHandle("le", words(afterMint, afterMint))
	actual := deriveHandle("select",
		words(le, afterMint, zero))
	debited := deriveHandle("sub", words(afterMint, actual))

	wantCorrect := deriveHandle("add", words(debited, actual))
	wantBuggy := deriveHandle("add", words(afterMint, actual))

	var amount [32]byte
	copy(amount[:], afterMint.Bytes())
	tk.send(t, tk.owner,
		"confidentialTransfer", tk.owner, amount)

	after := tk.balanceOf(t, tk.owner)

	if after == wantBuggy {
		t.Fatalf("self-transfer minted tokens: stored " +
			"balance is add(balance, actual), so the " +
			"debit was overwritten by the credit and " +
			"the balance grew by the amount " +
			"transferred to self")
	}
	if after != wantCorrect {
		t.Fatalf("stored balance = %x\nwant           "+
			"  = %x  (add of debited balance and "+
			"actual)", after, wantCorrect)
	}
}
