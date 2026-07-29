package fhe

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	cmn "github.com/cosmos/evm/precompiles/common"
)

//go:embed abi.json
var abiJSON string

// Precompile implements the Celar FHE precompile stub (task D1.5).
//
// Compute ops (add/sub/le/lt/eq/and/or/not/select/cast) and trivialEncrypt
// are STATELESS: the returned handle is a deterministic hash of the inputs.
// They never touch RunNativeAction, so they never count against
// MaxPrecompileCalls (S4).
//
// allow / requestReencrypt / requestReveal are STATEFUL: they run through
// RunNativeAction (G5 journaled path) and emit cosmos events. Real ACL
// storage is task D1.6; real KMS semantics are Track B.
type Precompile struct {
	cmn.Precompile
	abi abi.ABI
}

// NewPrecompile creates the Celar FHE precompile stub.
func NewPrecompile() (*Precompile, error) {
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("fhe precompile: parse abi: %w", err)
	}
	return &Precompile{
		Precompile: cmn.Precompile{
			KvGasConfig:          storetypes.GasConfig{},
			TransientKVGasConfig: storetypes.GasConfig{},
			ContractAddress:      common.HexToAddress(CelarFHEPrecompileAddress),
		},
		abi: parsed,
	}, nil
}

func (p Precompile) Name() string { return "celarfhe" }

// RequiredGas returns the flat stub gas for the method group.
func (p Precompile) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return 0
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return 0
	}
	switch method.Name {
	case VerifyInputMethod:
		return GasInput
	case AllowMethod, RequestReencryptMethod, RequestRevealMethod:
		return GasStateful
	default:
		return GasCompute
	}
}

// Run dispatches a call to the precompile.
func (p Precompile) Run(
	evm *vm.EVM,
	contract *vm.Contract,
	readonly bool,
) ([]byte, error) {
	input := contract.Input
	if len(input) < 4 {
		return nil, errors.New("fhe precompile: input too short")
	}
	method, err := p.abi.MethodById(input[:4])
	if err != nil {
		return nil, fmt.Errorf("fhe precompile: unknown method: %w", err)
	}
	argBz := input[4:]

	switch method.Name {
	// ---- stateless: input admission (stub) + compute ----------------------
	case VerifyInputMethod:
		args, err := method.Inputs.Unpack(argBz)
		if err != nil {
			return nil, err
		}
		proof, _ := args[1].([]byte)
		if len(proof) == 0 {
			return nil, errors.New("fhe precompile: empty proof rejected")
		}
		return p.packHandle(method, argBz)

	case TrivialEncryptMethod, AddMethod, SubMethod, LeMethod, LtMethod,
		EqMethod, AndMethod, OrMethod, NotMethod, SelectMethod, CastMethod:
		return p.packHandle(method, argBz)

	// ---- stateful: ACL + KMS gateway (G5 journaled path) ------------------
	case AllowMethod, RequestReencryptMethod, RequestRevealMethod:
		if readonly {
			return nil, vm.ErrWriteProtection
		}
		return p.RunNativeAction(evm, contract,
			func(ctx sdk.Context) ([]byte, error) {
				ctx.EventManager().EmitEvent(sdk.NewEvent(
					"celar_fhe_"+method.Name,
					sdk.NewAttribute("caller", contract.Caller().Hex()),
					sdk.NewAttribute("input",
						common.Bytes2Hex(crypto.Keccak256(argBz))),
				))
				if method.Name == AllowMethod {
					return nil, nil // allow returns void
				}
				return p.packHandle(method, argBz)
			})
	}
	return nil, fmt.Errorf("fhe precompile: unhandled method %s", method.Name)
}

// packHandle derives the deterministic stub handle for a call and ABI-packs
// it as the single bytes32 output:
//
//	handle = keccak256(domainTag || methodName || rawArgs)
func (p Precompile) packHandle(
	method *abi.Method,
	argBz []byte,
) ([]byte, error) {
	preimage := make([]byte, 0, len(domainTag)+len(method.Name)+len(argBz))
	preimage = append(preimage, []byte(domainTag)...)
	preimage = append(preimage, []byte(method.Name)...)
	preimage = append(preimage, argBz...)
	handle := crypto.Keccak256Hash(preimage)
	return method.Outputs.Pack(handle)
}
