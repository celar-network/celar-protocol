//go:build test

package token

import (
	"testing"

	"github.com/cosmos/evm/evmd/precompiles/fhe"

	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func streamLogs(logs []*evmtypes.Log) []*evmtypes.Log {
	topic := crypto.Keccak256Hash([]byte(fhe.StreamTopicPreimage)).Hex()
	var out []*evmtypes.Log
	for _, l := range logs {
		if len(l.Topics) > 0 && l.Topics[0] == topic {
			out = append(out, l)
		}
	}
	return out
}

// A transfer runs the branchless path through the precompile, so it should
// leave a stream a coprocessor could execute from: one event per op, in
// execution order, each decodable under the frozen schema.
func TestTransferEmitsAnExecutableStream(t *testing.T) {
	tk := deployToken(t)
	tk.send(t, tk.owner, "mint", tk.owner, uint64(100))

	bal := tk.balanceOf(t, tk.owner)
	var amt [32]byte
	copy(amt[:], bal.Bytes())
	logs := streamLogs(tk.sendCollectingLogs(t, tk.owner,
		"confidentialTransfer", tk.other, amt))

	if len(logs) == 0 {
		t.Fatal("a transfer produced no op-stream events — a coprocessor " +
			"would have nothing to execute for work the chain committed to")
	}

	var prev uint64
	for i, l := range logs {
		e, err := fhe.DecodeStreamEvent(l.Data)
		if err != nil {
			t.Fatalf("event %d does not decode under the frozen schema: %v", i, err)
		}
		if e.ResultHandle == (common.Hash{}) {
			t.Fatalf("event %d names a zero result handle", i)
		}
		if i > 0 && l.Index <= prev {
			t.Fatalf("event %d has log index %d, not after %d — canonical order "+
				"is (height, txIndex, logIndex) and a consumer relies on it",
				i, l.Index, prev)
		}
		prev = l.Index
	}
	t.Logf("transfer emitted %d stream events", len(logs))
}

// §1's load-bearing claim: logs are journaled, so a reverted call frame emits
// nothing and the stream never carries work from failed transactions.
//
// This exercises the MECHANISM rather than our call site. No path in the token
// contract both performs FHE work and then reverts — every revert there is a
// guard that fires before any op runs — so a contract-level version of this
// test needs a purpose-built contract — see opstream_revert_test.go,
// which drives one.
func TestRevertedFrameLeavesNoStreamEvent(t *testing.T) {
	tk := deployToken(t)
	before := len(tk.db.Logs())

	snap := tk.db.Snapshot()
	tk.db.AddLog(&ethtypes.Log{
		Address: common.HexToAddress(fhe.CelarFHEPrecompileAddress),
		Topics:  []common.Hash{crypto.Keccak256Hash([]byte(fhe.StreamTopicPreimage))},
		Data:    []byte{0x01},
	})
	if len(tk.db.Logs()) != before+1 {
		t.Fatal("precondition: the log was not recorded")
	}
	tk.db.RevertToSnapshot(snap)

	if got := len(tk.db.Logs()); got != before {
		t.Fatalf("a reverted frame left %d logs, expected %d — the stream would "+
			"carry work the chain disowned", got, before)
	}
}
