//go:build test

package token

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// inputProofEnvelope builds the public-input envelope verifyInput requires
// ahead of the proof body: version ‖ chainId ‖ target ‖ submitter ‖ txScope ‖
// expiry, fixed-width and big-endian.
//
// The fields are chain facts the precompile re-derives and compares, so each
// one here has to match what the call will observe rather than being filled in
// plausibly: the TARGET is the admitting caller, which is the token contract
// and not the account that sent the transaction; the SUBMITTER is the
// transaction origin; the EXPIRY must be at or after the current height and
// within the capped window.
//
// Built by hand rather than through a helper from the precompile package on
// purpose. If the envelope's layout changes, a test constructing it from the
// same code that parses it would keep passing — the two would agree with each
// other and with nothing else. That is the failure frontrun_test.go recorded
// when its helper re-implemented the derivation it was meant to check.
func inputProofEnvelope(
	t *testing.T,
	tk *tokenFixture,
	submitter common.Address,
	body []byte,
) []byte {
	t.Helper()
	cfg := evmtypes.GetEthChainConfig()
	if cfg == nil || cfg.ChainID == nil {
		t.Fatal("no eth chain config: the envelope's chain id cannot be built")
	}
	env := []byte{0x01}
	env = binary.BigEndian.AppendUint64(env, cfg.ChainID.Uint64())
	env = append(env, tk.addr.Bytes()...)
	env = append(env, submitter.Bytes()...)
	env = append(env, make([]byte, 32)...)
	env = binary.BigEndian.AppendUint64(env,
		uint64(tk.ctx.BlockHeight())+10) //nolint:gosec // test height
	return append(env, body...)
}

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

	// The proof is not verified yet — the precompile
	// checks only that it is non-empty. This asserts the
	// admission path works and records provenance, NOT
	// that admission is sound. It is not.
	ret := tk.send(t, tk.other,
		"transferFromExternal",
		tk.owner,
		[]byte("ciphertext-placeholder"),
		inputProofEnvelope(t, tk, tk.other, []byte("proof-body-placeholder")),
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
