//go:build test

package token

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/evmd/tests/integration"
	testapp "github.com/cosmos/evm/testutil/app"
	testconstants "github.com/cosmos/evm/testutil/constants"
	"github.com/cosmos/evm/testutil/integration/evm/factory"
	"github.com/cosmos/evm/testutil/integration/evm/grpc"
	"github.com/cosmos/evm/testutil/integration/evm/network"
	"github.com/cosmos/evm/testutil/keyring"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	"github.com/cosmos/evm/x/vm/statedb"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Drives a real transaction through the ante handler and the message server,
// rather than handing a StateDB to the keeper.
//
// # Why this test exists
//
// Every other emission test calls CallEVMWithData with a StateDB it created,
// then reads the logs back off that same object. Twelve of them pass. On a
// devnet, a committed transaction doing six FHE operations produces a block
// whose logsBloom is all zeros, while a contract's own LOG4 in the same
// transaction reaches its receipt normally.
//
// So the tests and the chain disagree, and nothing in the suite could see it:
// the difference is not Go versus a node, it is who creates the StateDB.
//
// The transaction here is a contract call, not a direct call to the precompile,
// because that is the shape the devnet failure has. A top-level transaction
// straight to 0x900 returns empty for reasons of its own, and diagnosing that
// would be diagnosing a path no real caller uses.
//
// mint() is the ideal subject: it does FHE work through the precompile AND
// emits its own LOG4. One transaction therefore carries both the suspect and
// the control, so "no logs at all" and "only the precompile's logs missing"
// cannot be confused.
const streamTopicPreimage = "celar.opstream.v1"

var fhePrecompile = common.HexToAddress("0x0000000000000000000000000000000000000900")

func TestStreamEventsSurviveTheNodePath(t *testing.T) {
	parsed, code := loadArtifact(t)

	creator := testapp.ToEvmAppCreator[evm.VMIntegrationApp](
		integration.CreateEvmd, "evm.VMIntegrationApp")

	keys := keyring.New(1)
	owner := keys.GetKey(0)

	customGenesis := network.CustomGenesisState{}
	fm := feemarkettypes.DefaultGenesisState()
	fm.Params.NoBaseFee = true
	customGenesis[feemarkettypes.ModuleName] = fm

	// Activation in genesis, which is how a real node does it. A post-hoc
	// SetParams write replaces the whole list (dropping every default
	// precompile) and raises an unanswerable question about whether the block
	// executing the transaction can see it. Genesis has neither problem.
	//
	// EvmDenom must be carried over explicitly: DefaultGenesisState names a
	// denom this network registers no bank metadata for, and InitGenesis panics
	// on the mismatch.
	evmGen := evmtypes.DefaultGenesisState()
	evmGen.Params.EvmDenom = testconstants.ExampleAttoDenom
	evmGen.Params.ActiveStaticPrecompiles = append(
		append([]string{}, evmtypes.DefaultStaticPrecompiles...),
		fhePrecompile.Hex(),
	)
	customGenesis[evmtypes.ModuleName] = evmGen

	nw := network.NewUnitTestNetwork(
		creator,
		network.WithPreFundedAccounts(keys.GetAllAccAddrs()...),
		network.WithCustomGenesis(customGenesis),
	)

	k := nw.App.GetEVMKeeper()

	handler := grpc.NewIntegrationHandler(nw)
	tf := factory.New(nw, handler)

	ctorArgs, err := parsed.Pack("", "Celar Test", "CELT", "ipfs://placeholder")
	if err != nil {
		t.Fatalf("pack constructor: %v", err)
	}
	deployRes, err := tf.ExecuteEthTx(owner.Priv, evmtypes.EvmTxArgs{
		Input:    append(code, ctorArgs...),
		GasLimit: 20_000_000,
	})
	if err != nil {
		t.Fatalf("deploy through the node path: %v", err)
	}
	deployed, err := evmtypes.DecodeTxResponse(deployRes.Data)
	if err != nil {
		t.Fatalf("decode deploy response: %v", err)
	}
	if deployed.VmError != "" {
		t.Fatalf("deploy reverted in the EVM: %q", deployed.VmError)
	}
	token := crypto.CreateAddress(owner.Addr, 0)

	// The factory reads the sender's nonce from committed state, so without
	// this the mint below reuses nonce 0 and the ante handler refuses it.
	if err := nw.NextBlock(); err != nil {
		t.Fatalf("commit the deploy: %v", err)
	}

	if c := statedb.New(nw.GetContext(), k,
		statedb.NewEmptyTxConfig()).GetCode(token); len(c) == 0 {
		t.Fatalf("no code at %s after the deploy: a call there would succeed "+
			"silently and produce no logs, which is indistinguishable from the "+
			"defect under investigation", token)
	}

	data, err := parsed.Pack("mint", owner.Addr, uint64(100))
	if err != nil {
		t.Fatalf("pack mint: %v", err)
	}
	res, err := tf.ExecuteEthTx(owner.Priv, evmtypes.EvmTxArgs{
		To:       &token,
		Input:    data,
		GasLimit: 10_000_000,
	})
	if err != nil {
		t.Fatalf("mint through the node path: %v", err)
	}
	if res.Code != 0 {
		t.Fatalf("mint rejected: code %d, log %s", res.Code, res.Log)
	}

	decoded, err := evmtypes.DecodeTxResponse(res.Data)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded.VmError != "" {
		t.Fatalf("mint reverted in the EVM: %q. Nothing about emission is "+
			"knowable from a frame that failed", decoded.VmError)
	}

	// The control. mint() cannot reach its own LOG4 without the precompile
	// having returned usable handles, so a contract log here establishes that
	// the FHE work really happened in this transaction.
	want := crypto.Keccak256Hash([]byte(streamTopicPreimage))
	var contractLogs, streamLogs int
	for _, lg := range decoded.Logs {
		switch common.HexToAddress(lg.Address) {
		case token:
			contractLogs++
		case fhePrecompile:
			if len(lg.Topics) > 0 && common.HexToHash(lg.Topics[0]) == want {
				streamLogs++
			}
		}
	}
	t.Logf("node path: %d log(s) total, %d from the token, %d op-stream",
		len(decoded.Logs), contractLogs, streamLogs)

	// The response's Logs field is empty even for the token's own LOG4, which
	// does reach receipts on a devnet — so logs are carried somewhere else and
	// asserting on that field measures nothing. Dump what the transaction
	// actually produced.
	for _, ev := range res.Events {
		keys := make([]string, 0, len(ev.Attributes))
		for _, at := range ev.Attributes {
			v := at.Value
			if len(v) > 60 {
				v = v[:60] + "..."
			}
			keys = append(keys, at.Key+"="+v)
		}
		t.Logf("event %s: %v", ev.Type, keys)
	}

	if contractLogs == 0 {
		t.Fatalf("the token emitted no log of its own, so this test is not "+
			"measuring the precompile: %d log(s) total", len(decoded.Logs))
	}
	if streamLogs == 0 {
		t.Fatal("reproduced: the token's own log reached the response and the " +
			"precompile's op-stream events did not. The defect is at or below " +
			"the message server, not in the devnet configuration")
	}
}
