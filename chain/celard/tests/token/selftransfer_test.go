//go:build test

package token

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

// deriveHandle is the COMPUTE derivation, unchanged by the state-entry
// amendment: compute results bind no principal, because their subject is
// whatever their operands already carry.
func deriveHandle(method string, args []byte) common.Hash {
	p := append([]byte(fheDomainTag), []byte(method)...)
	return crypto.Keccak256Hash(append(p, args...))
}

// deriveStateEntryHandle mirrors the precompile's state-entry derivation:
// domainTag || method || caller || principal || rawArgs.
//
// ⚠️ This RE-IMPLEMENTS the derivation, which is the hazard frontrun_test.go
// exists to record: its helper did the same, and the first run after the fix
// came back green while measuring a formula the chain had stopped using. It
// survives here only because these tests need a handle the contract has not
// returned to them. The safer shape is to read the handle back from the
// contract or the op-stream event instead of predicting it, and that is worth
// doing separately rather than inside the amendment.
func deriveStateEntryHandle(
	tk *tokenFixture,
	method string,
	principal common.Address,
	args []byte,
) common.Hash {
	p := append([]byte(fheDomainTag), []byte(method)...)
	p = append(p, tk.addr.Bytes()...)
	p = append(p, principal.Bytes()...)
	return crypto.Keccak256Hash(append(p, args...))
}

func words(hs ...common.Hash) []byte {
	out := make([]byte, 0, 32*len(hs))
	for _, h := range hs {
		out = append(out, h.Bytes()...)
	}
	return out
}

func trivialArgs(v uint64, principal common.Address) []byte {
	out := common.LeftPadBytes(
		new(big.Int).SetUint64(v).Bytes(), 32)
	out = append(out, common.LeftPadBytes(
		big.NewInt(64).Bytes(), 32)...)
	return append(out, common.LeftPadBytes(principal.Bytes(), 32)...)
}

func TestSelfTransferDoesNotMint(t *testing.T) {
	tk := deployToken(t)

	// The owner's zero and the minted amount both belong to the owner: mint
	// names the recipient as the principal. The zero that select falls back on
	// is the contract's own scratch constant and is now a different handle.
	ownerZero := deriveStateEntryHandle(tk, "trivialEncrypt",
		tk.owner, trivialArgs(0, tk.owner))
	scratchZero := deriveStateEntryHandle(tk, "trivialEncrypt",
		tk.addr, trivialArgs(0, tk.addr))
	minted := deriveStateEntryHandle(tk, "trivialEncrypt",
		tk.owner, trivialArgs(100, tk.owner))
	afterMint := deriveHandle("add", words(ownerZero, minted))

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
		words(le, afterMint, scratchZero))
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
