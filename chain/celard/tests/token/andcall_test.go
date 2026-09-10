//go:build test

package token

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// The four checks below were written in the review, before
// the implementation existed. They are
// reproduced in that order and not reordered to suit the
// code, which is the whole point of pre-specifying them.

const receiversDir = "../../../contracts/out/AndCallReceivers.sol/"

type receiver struct {
	abi  abi.ABI
	addr common.Address
}

func deployReceiver(
	t *testing.T, f *tokenFixture, name string, ctorArgs ...interface{},
) receiver {
	t.Helper()
	parsed, code := loadArtifactAt(t, receiversDir+name+".json")
	packed, err := parsed.Pack("", ctorArgs...)
	if err != nil {
		t.Fatalf("pack %s constructor: %v", name, err)
	}
	nonce := f.db.GetNonce(f.owner)
	if _, err := f.k.CallEVMWithData(
		f.ctx, f.db, f.owner, nil, append(code, packed...),
		true, false, big.NewInt(20_000_000),
	); err != nil {
		t.Fatalf("deploy %s: %v", name, err)
	}
	return receiver{abi: parsed, addr: crypto.CreateAddress(f.owner, nonce)}
}

func (r receiver) readHash(t *testing.T, f *tokenFixture, method string) common.Hash {
	t.Helper()
	data, err := r.abi.Pack(method)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	res, err := f.k.CallEVMWithData(
		f.ctx, f.db, f.owner, &r.addr, data,
		true, false, big.NewInt(10_000_000))
	if err != nil {
		t.Fatalf("call %s: %v", method, err)
	}
	out, err := r.abi.Unpack(method, res.Ret)
	if err != nil {
		t.Fatalf("unpack %s: %v", method, err)
	}
	arr := out[0].([32]byte)
	return common.BytesToHash(arr[:])
}

func (r receiver) readBool(t *testing.T, f *tokenFixture, method string) bool {
	t.Helper()
	data, err := r.abi.Pack(method)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	res, err := f.k.CallEVMWithData(
		f.ctx, f.db, f.owner, &r.addr, data,
		true, false, big.NewInt(10_000_000))
	if err != nil {
		t.Fatalf("call %s: %v", method, err)
	}
	out, err := r.abi.Unpack(method, res.Ret)
	if err != nil {
		t.Fatalf("unpack %s: %v", method, err)
	}
	return out[0].(bool)
}

func transferEvents(logs []*evmtypes.Log) []*evmtypes.Log {
	topic := crypto.Keccak256Hash(
		[]byte("ConfidentialTransfer(address,address,bytes32)"))
	var out []*evmtypes.Log
	for _, l := range logs {
		if len(l.Topics) > 0 && common.HexToHash(l.Topics[0]) == topic {
			out = append(out, l)
		}
	}
	return out
}

// Mints emit a transfer from the zero address, and the
// StateDB's log buffer accumulates across calls in a fixture
// — so the mint that set a test up is still present when the
// call under test is inspected. Dropping it is not
// cosmetic: indexing from the front otherwise picks the
// mint's amount handle, which is a different handle from the
// one transferred, and an assertion against it passes no
// matter what the refund does.
func withoutMints(ev []*evmtypes.Log) []*evmtypes.Log {
	var out []*evmtypes.Log
	zero := common.Hash{}.Hex()
	for _, l := range ev {
		if len(l.Topics) > 1 && l.Topics[1] != zero {
			out = append(out, l)
		}
	}
	return out
}

// 1. A re-entrant call inside the callback cannot DISPLACE a
// claimant.
//
// Asserted through what membership authorises rather than by
// reading the mapping, which is private: the original holder
// of a shared handle must still be able to spend it after a
// re-entrant call has recorded new claimants. Under the
// first-writer-wins rule this replaced, that spend reverted.
//
// Note the assertion is NOT that the re-entrant call was
// refused. It succeeds, deliberately — the guard is scoped to
// the callback path, and a receiver making an ordinary
// transfer is legitimate.
func TestReentrantCallbackCannotDisplaceAClaimant(t *testing.T) {
	f := deployToken(t)

	// Two accounts minted the same amount share a balance
	// handle: handles are deterministic and the traces are
	// identical. That collision is the premise, not a bug
	// being tested here.
	f.send(t, f.owner, "mint", f.owner, uint64(100))
	f.send(t, f.owner, "mint", f.other, uint64(100))
	shared := f.balanceOf(t, f.other)
	if shared != f.balanceOf(t, f.owner) {
		t.Fatalf("premise failed: equal mints did not collide")
	}

	r := deployReceiver(t, f, "ReentrantReceiver", f.addr, f.other)
	f.send(t, f.owner, "confidentialTransferAndCall",
		r.addr, shared, []byte{})

	if !r.readBool(t, f, "reentered") {
		t.Fatalf("receiver never re-entered; the test proves nothing")
	}
	// The claim survives: `other` still spends the shared handle.
	if err := f.sendExpectingRevert(t, f.other,
		"confidentialTransfer", f.owner, shared); err != nil {
		t.Fatalf("re-entrancy displaced a claimant: %v", err)
	}
}

// 2. The callback fires AFTER the credit.
//
// The receiver reads its own balance during the callback. If
// the hook fired between the debit and the credit it would
// observe the pre-credit handle, and the self-transfer fix's
// assumption that nothing interleaves would be false.
func TestCallbackFiresAfterTheCredit(t *testing.T) {
	f := deployToken(t)
	f.send(t, f.owner, "mint", f.owner, uint64(100))
	amount := f.balanceOf(t, f.owner)

	r := deployReceiver(t, f, "AcceptingReceiver", f.addr)
	f.send(t, f.owner, "confidentialTransferAndCall",
		r.addr, amount, []byte{})

	seen := r.readHash(t, f, "seenBalance")
	if seen != f.balanceOf(t, r.addr) {
		t.Fatalf("callback saw balance %s, settled balance is %s:"+
			" the hook fired before the credit",
			seen, f.balanceOf(t, r.addr))
	}
}

// 3. The refund emits its own transfer event, and an indexer
// can tell it from the original.
func TestRefundEmitsItsOwnDistinguishableEvent(t *testing.T) {
	f := deployToken(t)
	f.send(t, f.owner, "mint", f.owner, uint64(100))
	amount := f.balanceOf(t, f.owner)

	r := deployReceiver(t, f, "RefusingReceiver")
	logs := f.sendCollectingLogs(t, f.owner,
		"confidentialTransferAndCall", r.addr, amount, []byte{})

	ev := withoutMints(transferEvents(logs))
	if len(ev) != 2 {
		t.Fatalf("want 2 transfer events (transfer + refund), got %d", len(ev))
	}
	// Direction is what distinguishes them, and both parties
	// are indexed topics, so a filter can separate them.
	if ev[0].Topics[1] != ev[1].Topics[2] || ev[0].Topics[2] != ev[1].Topics[1] {
		t.Fatalf("refund is not the reverse of the transfer:"+
			" %v then %v", ev[0].Topics, ev[1].Topics)
	}
}

// 4. A misbehaving receiver KEEPS the tokens.
//
// The receiver forwards what it was sent, then refuses. The
// refund is an ordinary transfer back, so against a drained
// balance the branchless rule moves zero rather than
// reverting — the sender is not made whole.
//
// ⚠️ SCOPE, stated because the same trap was hit before: this
// asserts the SHAPE, not the value. The chain layer cannot
// see amounts, so "the refund moved zero" is not directly
// observable here — the refund's amount handle differing from
// the original is consistent with a zero move but does not
// prove one. The value-level assertion belongs at the
// backend, where decryption exists, exactly as the shared-
// handle question was settled. Tracked internally.
func TestMisbehavingReceiverKeepsTheTokens(t *testing.T) {
	f := deployToken(t)
	f.send(t, f.owner, "mint", f.owner, uint64(100))
	amount := f.balanceOf(t, f.owner)

	r := deployReceiver(t, f, "SpendthriftReceiver", f.addr, f.other)
	logs := f.sendCollectingLogs(t, f.owner,
		"confidentialTransferAndCall", r.addr, amount, []byte{})

	ev := withoutMints(transferEvents(logs))
	if len(ev) != 3 {
		t.Fatalf("want transfer + onward spend + refund, got %d", len(ev))
	}
	refund := ev[len(ev)-1]
	if refund.Topics[3] == ev[0].Topics[3] {
		t.Fatalf("refund carries the ORIGINAL amount handle:" +
			" it cannot have moved zero from a drained balance")
	}
}
