//go:build test

package token

// The contract-level counterpart to TestRevertedFrameLeavesNoStreamEvent,
// which proves the journal MECHANISM drops logs on revert but drives
// StateDB directly. This drives the precompile through a contract, which
// is where the property actually has to hold.
//
// Package placement is wrong and deliberately so: this is not a token
// test, but the EVM fixture — network setup, precompile activation —
// lives in this package, and a second package hosting one contract would
// duplicate exactly the scaffolding most likely to drift out of sync.
// Moving the fixture to a neutral package is the right fix and is out of
// scope here.

import (
	"math/big"
	"testing"

	"github.com/cosmos/evm/evmd/precompiles/fhe"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const probeArtifactRel = "../../../contracts/out/" +
	"StreamRevertProbe.sol/StreamRevertProbe.json"

// streamLogsEth is streamLogs over StateDB logs rather than response
// logs. A reverted call returns no response at all, so the only place a
// leaked event could be observed is the state itself.
func streamLogsEth(logs []*ethtypes.Log) []*ethtypes.Log {
	topic := crypto.Keccak256Hash([]byte(fhe.StreamTopicPreimage))
	var out []*ethtypes.Log
	for _, l := range logs {
		if len(l.Topics) > 0 && l.Topics[0] == topic {
			out = append(out, l)
		}
	}
	return out
}

type probeContract struct {
	abi  abi.ABI
	addr common.Address
}

func deployProbe(t *testing.T, f *tokenFixture) probeContract {
	t.Helper()
	parsed, code := loadArtifactAt(t, probeArtifactRel)
	nonce := f.db.GetNonce(f.owner)
	if _, err := f.k.CallEVMWithData(
		f.ctx, f.db, f.owner, nil, code,
		true, false, big.NewInt(20_000_000),
	); err != nil {
		t.Fatalf("deploy probe: %v", err)
	}
	return probeContract{
		abi:  parsed,
		addr: crypto.CreateAddress(f.owner, nonce),
	}
}

func (p probeContract) call(
	t *testing.T, f *tokenFixture, method string,
) error {
	t.Helper()
	data, err := p.abi.Pack(method)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	_, err = f.k.CallEVMWithData(
		f.ctx, f.db, f.owner, &p.addr, data,
		true, false, big.NewInt(20_000_000),
	)
	return err
}

func streamCount(f *tokenFixture) int {
	return len(streamLogsEth(f.db.Logs()))
}

// A contract that does real FHE work and then reverts must leave no
// stream event behind, or a coprocessor would execute work the chain
// disowned.
//
// workAndKeep() is the control and it is not decoration: the assertion
// "no events after a revert" passes trivially against a contract that
// emits none, which is the same defect class as a config assertion
// tested against its own default. The control proves the path emits.
func TestRevertedContractFrameLeavesNoStreamEvent(t *testing.T) {
	f := deployToken(t)
	p := deployProbe(t, f)

	base := streamCount(f)
	if err := p.call(t, f, "workAndKeep"); err != nil {
		t.Fatalf("control call reverted, so it controls nothing: %v", err)
	}
	control := streamCount(f) - base
	// Six: two asEuint64 (trivialEncrypt), then add, le, select,
	// sub. Observed first and pinned afterwards — a count taken
	// from reading the Solidity would assert my reading of the
	// contract rather than the chain's behaviour. Pinned rather
	// than checked for non-zero so that an op which silently
	// stops emitting is caught; a zero-check would miss five of
	// six going missing.
	const wantControl = 6
	if control != wantControl {
		t.Fatalf("control emitted %d stream events, want %d — if this "+
			"dropped, an op stopped emitting and the revert assertion "+
			"below is weaker than it looks", control, wantControl)
	}
	for i, l := range streamLogsEth(f.db.Logs())[base:] {
		if _, err := fhe.DecodeStreamEvent(l.Data); err != nil {
			t.Fatalf("control event %d does not decode: %v", i, err)
		}
	}
	t.Logf("control emitted %d stream events", control)

	afterControl := streamCount(f)
	if err := p.call(t, f, "workThenRevert"); err == nil {
		t.Fatal("workThenRevert did not revert; the test proves nothing")
	}
	if leaked := streamCount(f) - afterControl; leaked != 0 {
		t.Fatalf("a reverted contract frame left %d stream events — a "+
			"coprocessor would execute %d ops the chain disowned",
			leaked, leaked)
	}
}
