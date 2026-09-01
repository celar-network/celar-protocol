//go:build test

package token

import (
	"encoding/json"
	"github.com/cosmos/evm/evmd/tests/integration"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	evm "github.com/cosmos/evm"
	testapp "github.com/cosmos/evm/testutil/app"
	"github.com/cosmos/evm/testutil/integration/evm/network"
	"github.com/cosmos/evm/testutil/keyring"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	"github.com/cosmos/evm/x/vm/statedb"
)

// Harness spike: deploy the confidential token against the
// real app — real precompile at 0x900, real StateDB — and
// read one plaintext getter. No behavioural assertions yet;
// the point is to prove the harness before relying on it.

const artifactRel = "../../../contracts/out/" +
	"ConfidentialERC20.sol/ConfidentialERC20.json"

type forgeArtifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

func loadArtifact(t *testing.T) (abi.ABI, []byte) {
	t.Helper()
	return loadArtifactAt(t, artifactRel)
}

// loadArtifactAt loads any forge artifact by relative path.
// Split out of loadArtifact so a second contract can be
// deployed into this fixture without duplicating the
// CI-fatal / locally-skip decision, which is the part that
// must not drift between callers.
func loadArtifactAt(t *testing.T, rel string) (abi.ABI, []byte) {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("resolve artifact path: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		// Fatal in CI, skip locally: a silently skipped
		// test is indistinguishable from a passing one,
		// and this is the only thing exercising the
		// contract.
		if os.Getenv("CI") != "" {
			t.Fatalf("artifact missing in CI — run "+
				"`forge build` first: %v", err)
		}
		t.Skipf("artifact missing; run `forge build` in "+
			"chain/contracts (%v)", err)
	}
	var a forgeArtifact
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("parse artifact: %v", err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(a.ABI)))
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	code := common.FromHex(a.Bytecode.Object)
	if len(code) == 0 {
		t.Fatal("artifact carries no bytecode")
	}
	return parsed, code
}

func TestDeployConfidentialERC20(t *testing.T) {
	parsed, code := loadArtifact(t)

	creator := testapp.ToEvmAppCreator[evm.VMIntegrationApp](
		integration.CreateEvmd, "evm.VMIntegrationApp")

	keys := keyring.New(2)

	customGenesis := network.CustomGenesisState{}

	fm := feemarkettypes.DefaultGenesisState()
	fm.Params.NoBaseFee = true
	customGenesis[feemarkettypes.ModuleName] = fm

	// Registering the precompile in app.go is not enough —
	// it must also be active in evm params, which is a
	// second, independent switch. The devnet's genesis
	// patch sets exactly this list, ICS20 deliberately
	// excluded (ASA-2026-002). Without it, calls to 0x900
	// hit no code, return empty, and TFHE._call's
	// abi.decode reverts several frames from the cause.

	nw := network.NewUnitTestNetwork(
		creator,
		network.WithPreFundedAccounts(
			keys.GetAllAccAddrs()...),
		network.WithCustomGenesis(customGenesis),
	)

	ctx := nw.GetContext()
	k := nw.App.GetEVMKeeper()
	// Registration in app.go is not enough — the precompile
	// must also be listed in evm params, a second and
	// independent switch. Set it on the test context rather
	// than in genesis: replacing the evm genesis wholesale
	// drops the chain's configured denom and params, which
	// InitGenesis then rejects.
	prm := k.GetParams(ctx)
	prm.ActiveStaticPrecompiles = []string{
		"0x0000000000000000000000000000000000000900",
	}
	if err := k.SetParams(ctx, prm); err != nil {
		t.Fatalf("activate fhe precompile: %v", err)
	}
	t.Logf("active precompiles: %v",
		k.GetParams(ctx).ActiveStaticPrecompiles)

	db := statedb.New(ctx, k, statedb.NewEmptyTxConfig())
	from := keys.GetKey(0).Addr

	t.Logf("active precompiles: %v",
		k.GetParams(ctx).ActiveStaticPrecompiles)

	ctorArgs, err := parsed.Pack(
		"", "Celar Test", "CELT", "ipfs://placeholder")
	if err != nil {
		t.Fatalf("pack constructor: %v", err)
	}

	nonce := db.GetNonce(from)
	if _, err := k.CallEVMWithData(
		ctx, db, from, nil, append(code, ctorArgs...),
		true, false, big.NewInt(20_000_000),
	); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	addr := crypto.CreateAddress(from, nonce)

	callData, err := parsed.Pack("name")
	if err != nil {
		t.Fatalf("pack name(): %v", err)
	}
	res, err := k.CallEVMWithData(
		ctx, db, from, &addr, callData,
		true, false, big.NewInt(5_000_000),
	)
	if err != nil {
		t.Fatalf("call name(): %v", err)
	}

	out, err := parsed.Unpack("name", res.Ret)
	if err != nil {
		t.Fatalf("unpack name(): %v", err)
	}
	if got := out[0].(string); got != "Celar Test" {
		t.Fatalf("name() = %q, want %q",
			got, "Celar Test")
	}
}
