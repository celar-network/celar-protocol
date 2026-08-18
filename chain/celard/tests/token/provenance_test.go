//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func unpackHandle(
	t *testing.T,
	tk *tokenFixture,
	method string,
	ret []byte,
) common.Hash {
	t.Helper()
	out, err := tk.abi.Unpack(method, ret)
	if err != nil {
		t.Fatalf("unpack %s: %v", method, err)
	}
	arr := out[0].([32]byte)
	return common.BytesToHash(arr[:])
}

// The provenance bookkeeping is only exercised through
// mint and confidentialTransfer. This covers the third
// path that issues a handle — external admission — and the
// forwarding case, where a recipient spends what they
// received. Bookkeeping that is right on the paths you
// tested and wrong on the one you didn't is the whole
// hazard of choosing contract-side provenance over an
// access-control read on the precompile.
func TestExternalAdmissionIsAccepted(t *testing.T) {
	tk := deployToken(t)

	// The proof is not verified yet (C1) — the precompile
	// checks only that it is non-empty. This asserts the
	// admission path works and records provenance, NOT
	// that admission is sound. It is not.
	ret := tk.send(t, tk.other,
		"transferFromExternal",
		tk.owner,
		[]byte("ciphertext-placeholder"),
		[]byte("proof-placeholder"),
	)
	if h := unpackHandle(t, tk,
		"transferFromExternal", ret); h == (common.Hash{}) {
		t.Fatal("admission returned a zero handle")
	}
}

func TestEmptyProofIsRefused(t *testing.T) {
	tk := deployToken(t)

	err := tk.sendExpectingRevert(t, tk.other,
		"transferFromExternal",
		tk.owner,
		[]byte("ciphertext-placeholder"),
		[]byte{},
	)
	if err == nil {
		t.Fatal("an empty input proof was accepted")
	}
}

// A recipient must be able to forward what they received:
// _record(actual, to) is what makes the returned handle
// spendable by the party who got it. Without it the
// provenance guard would refuse every onward transfer and
// value would be trapped after one hop.
func TestRecipientCanForwardWhatTheyReceived(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	bal := tk.balanceOf(t, tk.owner)
	var amount [32]byte
	copy(amount[:], bal.Bytes())

	ret := tk.send(t, tk.owner,
		"confidentialTransfer", tk.other, amount)
	actual := unpackHandle(t, tk,
		"confidentialTransfer", ret)

	// The recipient now forwards exactly what arrived.
	var onward [32]byte
	copy(onward[:], actual.Bytes())

	third := common.HexToAddress(
		"0x00000000000000000000000000000000000000ff")
	if err := tk.sendExpectingRevert(t, tk.other,
		"confidentialTransfer", third, onward,
	); err != nil {
		t.Fatalf("recipient could not forward the handle "+
			"they received — provenance is recorded to "+
			"the wrong party, so value is trapped after "+
			"one hop: %v", err)
	}
}
