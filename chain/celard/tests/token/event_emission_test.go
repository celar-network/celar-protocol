//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	evmtypes "github.com/cosmos/evm/x/vm/types"
)

func transferTopics(
	t *testing.T,
	logs []*evmtypes.Log,
) []string {
	t.Helper()
	want := crypto.Keccak256Hash([]byte(
		"ConfidentialTransfer(address,address,bytes32)"))
	for _, lg := range logs {
		if len(lg.Topics) > 0 && lg.Topics[0] == want.Hex() {
			return lg.Topics
		}
	}
	return nil
}

// The event must fire even when nothing moved. Suppressing
// it for a zero amount would leak the predicate through
// the presence of a log: an observer learns the comparison
// from whether an event exists, which is the branchless
// rule violated through logs instead of control flow.
//
// A zero-value transfer is constructible because the
// encrypted zero is a handle like any other, and the
// sender was issued it when their balance was lazily
// initialised.
func TestEventFiresOnZeroValueTransfer(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	// The owner's own zero: _ensure records it to the account it belongs to,
	// so it is the zero handle this caller was issued and may spend.
	zero := deriveStateEntryHandle(tk, "trivialEncrypt",
		tk.owner, trivialArgs(0, tk.owner))
	var amount [32]byte
	copy(amount[:], zero.Bytes())

	logs := tk.sendCollectingLogs(t, tk.owner,
		"confidentialTransfer", tk.other, amount)

	topics := transferTopics(t, logs)
	if topics == nil {
		t.Fatal("no transfer event on a zero-value " +
			"transfer; log presence would tell an " +
			"observer the amount was zero")
	}
	if len(topics) != 4 {
		t.Fatalf("event has %d topics, want 4",
			len(topics))
	}
}

// The standard says mint should report a zero sender.
// Indexers use it to distinguish issuance from movement.
func TestMintReportsZeroSender(t *testing.T) {
	tk := deployToken(t)

	logs := tk.sendCollectingLogs(t, tk.owner,
		"mint", tk.owner, uint64(100))

	topics := transferTopics(t, logs)
	if topics == nil {
		t.Fatal("mint emitted no transfer event")
	}
	var zeroAddr common.Hash // 32 zero bytes
	if topics[1] != zeroAddr.Hex() {
		t.Fatalf("mint reported sender %s, want the "+
			"zero address — issuance is otherwise "+
			"indistinguishable from a transfer",
			topics[1])
	}
}
