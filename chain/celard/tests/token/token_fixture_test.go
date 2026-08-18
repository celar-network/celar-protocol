//go:build test

package token

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	evm "github.com/cosmos/evm"
	"github.com/cosmos/evm/evmd/tests/integration"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/cosmos/evm/testutil/integration/evm/network"
	"github.com/cosmos/evm/testutil/keyring"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	evmkeeper "github.com/cosmos/evm/x/vm/keeper"
	"github.com/cosmos/evm/x/vm/statedb"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

// Shared fixture: an initialised network with the FHE
// precompile active, the token deployed, and helpers to
// call it. Every behavioural test needs exactly this.
type tokenFixture struct {
	ctx   sdk.Context
	k     *evmkeeper.Keeper
	db    *statedb.StateDB
	abi   abi.ABI
	addr  common.Address
	owner common.Address
	other common.Address
	nw    *network.UnitTestNetwork
}

func deployToken(t *testing.T) *tokenFixture {
	t.Helper()
	parsed, code := loadArtifact(t)

	creator := testapp.ToEvmAppCreator[evm.VMIntegrationApp](
		integration.CreateEvmd, "evm.VMIntegrationApp")

	keys := keyring.New(2)

	customGenesis := network.CustomGenesisState{}
	fm := feemarkettypes.DefaultGenesisState()
	fm.Params.NoBaseFee = true
	customGenesis[feemarkettypes.ModuleName] = fm

	nw := network.NewUnitTestNetwork(
		creator,
		network.WithPreFundedAccounts(
			keys.GetAllAccAddrs()...),
		network.WithCustomGenesis(customGenesis),
	)

	ctx := nw.GetContext()
	k := nw.App.GetEVMKeeper()

	// Registration in app.go and activation in evm params
	// are independent switches; without the second, calls
	// to 0x900 return empty and revert in abi.decode.
	prm := k.GetParams(ctx)
	prm.ActiveStaticPrecompiles = []string{
		"0x0000000000000000000000000000000000000900",
	}
	if err := k.SetParams(ctx, prm); err != nil {
		t.Fatalf("activate fhe precompile: %v", err)
	}

	db := statedb.New(ctx, k, statedb.NewEmptyTxConfig())
	owner := keys.GetKey(0).Addr
	other := keys.GetKey(1).Addr

	ctorArgs, err := parsed.Pack(
		"", "Celar Test", "CELT", "ipfs://placeholder")
	if err != nil {
		t.Fatalf("pack constructor: %v", err)
	}
	nonce := db.GetNonce(owner)
	if _, err := k.CallEVMWithData(
		ctx, db, owner, nil, append(code, ctorArgs...),
		true, false, big.NewInt(20_000_000),
	); err != nil {
		t.Fatalf("deploy: %v", err)
	}

	return &tokenFixture{
		nw:    nw,
		ctx:   ctx,
		k:     k,
		db:    db,
		abi:   parsed,
		addr:  crypto.CreateAddress(owner, nonce),
		owner: owner,
		other: other,
	}
}

// send calls a contract method from `caller`, returning the
// raw return data. Failures are fatal with the method named,
// because a revert several frames deep is otherwise very
// hard to attribute.
func (f *tokenFixture) send(
	t *testing.T,
	caller common.Address,
	method string,
	args ...interface{},
) []byte {
	t.Helper()
	data, err := f.abi.Pack(method, args...)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	res, err := f.k.CallEVMWithData(
		f.ctx, f.db, caller, &f.addr, data,
		true, false, big.NewInt(10_000_000),
	)
	if err != nil {
		t.Fatalf("call %s: %v", method, err)
	}
	return res.Ret
}

// sendExpectingRevert is for tests where refusal is the
// property under test.
func (f *tokenFixture) sendExpectingRevert(
	t *testing.T,
	caller common.Address,
	method string,
	args ...interface{},
) error {
	t.Helper()
	data, err := f.abi.Pack(method, args...)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	_, err = f.k.CallEVMWithData(
		f.ctx, f.db, caller, &f.addr, data,
		true, false, big.NewInt(10_000_000),
	)
	return err
}

func (f *tokenFixture) balanceOf(
	t *testing.T,
	who common.Address,
) common.Hash {
	t.Helper()
	ret := f.send(t, f.owner,
		"confidentialBalanceOf", who)
	out, err := f.abi.Unpack(
		"confidentialBalanceOf", ret)
	if err != nil {
		t.Fatalf("unpack balance: %v", err)
	}
	arr := out[0].([32]byte)
	return common.BytesToHash(arr[:])
}

// A reverted call leaves the context's gas meter in a state
// that panics on the next use, so any test expecting a
// revert must take a fresh context before continuing.
// Deliberately not NextBlock(): rolling the block discards
// the writes made against this context, including the
// deployed contract itself.
func (f *tokenFixture) refresh(t *testing.T) {
	t.Helper()
	// The revert leaves the shared context's gas meter
	// poisoned, and GetContext hands back that same
	// context — so the meter has to be replaced, not
	// merely re-fetched. NextBlock would also clear it,
	// but discards the writes made against this context,
	// the deployed contract included.
	f.ctx = f.nw.GetContext().WithGasMeter(
		storetypes.NewInfiniteGasMeter())
	f.db = statedb.New(
		f.ctx, f.k, statedb.NewEmptyTxConfig())
}

// send discards the response; event assertions need it.
func (f *tokenFixture) sendCollectingLogs(
	t *testing.T,
	caller common.Address,
	method string,
	args ...interface{},
) []*evmtypes.Log {
	t.Helper()
	data, err := f.abi.Pack(method, args...)
	if err != nil {
		t.Fatalf("pack %s: %v", method, err)
	}
	res, err := f.k.CallEVMWithData(
		f.ctx, f.db, caller, &f.addr, data,
		true, false, big.NewInt(10_000_000),
	)
	if err != nil {
		t.Fatalf("call %s: %v", method, err)
	}
	return res.Logs
}
