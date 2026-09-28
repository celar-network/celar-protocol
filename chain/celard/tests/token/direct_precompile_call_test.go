//go:build test

package token

import (
	"math/big"
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
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Settles whether a transaction sent straight to the precompile address runs
// it, with the precompile active in genesis.
//
// This question was answered wrongly once. Every earlier observation of an
// empty return was made while activation was not taking effect, so it measured
// an inactive precompile and was read as a defect in the call path.
func TestDirectTransactionToPrecompileAddress(t *testing.T) {
	creator := testapp.ToEvmAppCreator[evm.VMIntegrationApp](
		integration.CreateEvmd, "evm.VMIntegrationApp")

	keys := keyring.New(1)

	customGenesis := network.CustomGenesisState{}
	fm := feemarkettypes.DefaultGenesisState()
	fm.Params.NoBaseFee = true
	customGenesis[feemarkettypes.ModuleName] = fm

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
	tf := factory.New(nw, grpc.NewIntegrationHandler(nw))

	// The state-entry op takes a required principal. An EOA calling directly
	// names itself: there is no contract in the frame, so caller and principal
	// are the same address here, which is the degenerate case and still valid.
	sel := crypto.Keccak256(
		[]byte("trivialEncrypt(uint64,uint8,address)"))[:4]
	data := append([]byte{}, sel...)
	data = append(data, common.LeftPadBytes(big.NewInt(42).Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(big.NewInt(64).Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(keys.GetKey(0).Addr.Bytes(), 32)...)

	res, err := tf.ExecuteEthTx(keys.GetPrivKey(0), evmtypes.EvmTxArgs{
		To:       &fhePrecompile,
		Input:    data,
		GasLimit: 1_000_000,
	})
	if err != nil {
		t.Fatalf("transaction failed: %v", err)
	}
	decoded, err := evmtypes.DecodeTxResponse(res.Data)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}

	t.Logf("direct call: ret %d bytes, vmError %q, gasUsed %d, logs %d",
		len(decoded.Ret), decoded.VmError, decoded.GasUsed, len(decoded.Logs))

	if len(decoded.Ret) != 32 {
		t.Fatalf("a direct transaction to an active precompile returned %d "+
			"bytes and no error: it was treated as a plain account",
			len(decoded.Ret))
	}
	if len(decoded.Logs) == 0 {
		t.Fatal("the precompile ran but emitted no stream event")
	}
}
