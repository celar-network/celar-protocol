//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// The standard fixes this signature with ALL THREE
// parameters indexed, the amount handle included.
// Indexers filter on topics, so a non-indexed amount
// makes these transfers invisible to the ecosystem — a
// failure that is silent locally and only visible to
// someone else's tooling, which is why it gets a test
// rather than a declaration.
func TestTransferEventMatchesTheStandard(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	bal := tk.balanceOf(t, tk.owner)
	var amount [32]byte
	copy(amount[:], bal.Bytes())

	logs := tk.sendCollectingLogs(t, tk.owner,
		"confidentialTransfer", tk.other, amount)

	want := crypto.Keccak256Hash([]byte(
		"ConfidentialTransfer(address,address,bytes32)"))

	found := false
	for _, lg := range logs {
		if len(lg.Topics) == 0 ||
			lg.Topics[0] != want.Hex() {
			continue
		}
		found = true

		// signature + from + to + amount
		if len(lg.Topics) != 4 {
			t.Fatalf("event carries %d topics, want 4 — "+
				"all three parameters must be indexed, "+
				"or ecosystem indexers cannot see these "+
				"transfers", len(lg.Topics))
		}
		if len(lg.Data) != 0 {
			t.Fatalf("event carries %d data bytes; every "+
				"parameter should be a topic",
				len(lg.Data))
		}
	}
	if !found {
		t.Fatalf("no transfer log with topic0 %s in %d "+
			"logs", want.Hex(), len(logs))
	}
}
