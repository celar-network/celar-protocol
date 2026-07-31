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
		h := p.deriveHandle(method, argBz)
		p.registerHandle(evm.StateDB, h, contract.Caller(),
			KTypeUnknown, readonly)
		return method.Outputs.Pack(h)

	case TrivialEncryptMethod, AddMethod, SubMethod, LeMethod, LtMethod,
		EqMethod, AndMethod, OrMethod, NotMethod, SelectMethod, CastMethod:
		h := p.deriveHandle(method, argBz)
		p.registerHandle(evm.StateDB, h, contract.Caller(),
			p.resultKType(evm.StateDB, method, argBz), readonly)
		return method.Outputs.Pack(h)

	// ---- stateful: ACL + KMS gateway (G5 journaled path) ------------------
	case AllowMethod:
		if readonly {
			return nil, vm.ErrWriteProtection
		}
		return p.runAllow(evm.StateDB, contract.Caller(), method, argBz)

	// ---- stateful : KMS gateway (journaled native-action path) ------------
	case RequestReencryptMethod, RequestRevealMethod:
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
				return p.packHandle(method, argBz)
			})
	}
	return nil, fmt.Errorf("fhe precompile: unhandled method %s", method.Name)
}

// deriveHandle computes the deterministic stub handle for a call:
//
//	handle = keccak256(domainTag || methodName || rawArgs)
func (p Precompile) deriveHandle(
	method *abi.Method,
	argBz []byte,
) common.Hash {
	preimage := make([]byte, 0, len(domainTag)+len(method.Name)+len(argBz))
	preimage = append(preimage, []byte(domainTag)...)
	preimage = append(preimage, []byte(method.Name)...)
	preimage = append(preimage, argBz...)
	return crypto.Keccak256Hash(preimage)
}

// packHandle derives the stub handle and ABI-Packs it as the single
// byte32 output.
func (p Precompile) packHandle(
	method *abi.Method,
	argBz []byte,
) ([]byte, error) {
	return method.Outputs.Pack(p.deriveHandle(method, argBz))
}

// resultType decides the plaintext type tag of a compute result:
// comparisons/booleans are ebool: tivicalEncrypt/cast carry an explicit k
// argument: add/sub/select inherit the first operand handle's registered
// type (unknown if the operand was never registered)
func (p Precompile) resultKType(
	db vm.StateDB,
	method *abi.Method,
	argBz []byte,
) uint8 {
	switch method.Name {
	case LeMethod, LtMethod, EqMethod, AndMethod, OrMethod, NotMethod:
		return KTypeEbool
	case TrivialEncryptMethod, CastMethod:
		args, err := method.Inputs.Unpack(argBz)
		if err != nil {
			return KTypeUnknown
		}
		if k, ok := args[len(args)-1].(uint8); ok {
			return k
		}
		return KTypeUnknown
	case AddMethod, SubMethod:
		return p.operandKType(db, argBz, 0)
	case SelectMethod:
		return p.operandKType(db, argBz, 0)
	}
	return KTypeUnknown
}

// operandKType reads the registered type of the idx-th bytes32 argument.
func (p Precompile) operandKType(
	db vm.StateDB,
	argBz []byte,
	idx int,
) uint8 {
	off := idx * 32
	if len(argBz) < off+32 {
		return KTypeUnknown
	}
	meta := p.getMeta(db, common.BytesToHash(argBz[off:off+32]))
	if !metaExist(meta) {
		return KTypeUnknown
	}
	return metaKType(meta)
}

// runAllow enforces the owner-only write rule and records the grant:
// only the account that created h(per the handle registry) may add ACL
// entries for it. Grants are additive perm bits in ach[h][grantee].
func (p Precompile) runAllow(
	db vm.StateDB,
	caller common.Address,
	method *abi.Method,
	argBz []byte,
) ([]byte, error) {
	args, err := method.Inputs.Unpack(argBz)
	if err != nil {
		return nil, err
	}
	hb, ok := args[0].([32]byte)
	if !ok {
		return nil, errors.New("fhe preompile:allow: bad handle arg")
	}
	var grantee common.Address
	switch v := args[1].(type) {
	case common.Address:
		grantee = v
	case [20]byte:
		grantee = common.Address(v)
	default:
		return nil, fmt.Errorf("fhe precompile: allow: bad account arg (%T)", args[1])
	}
	var perm (uint8)
	switch v := args[2].(type) {
	case uint8:
		perm = v
	default:
		return nil, fmt.Errorf("fhe precompile: allow: bad perm arg (%T)", args[2])
	}

	h := common.Hash(hb)
	meta := p.getMeta(db, h)
	if !metaExist(meta) {
		return nil, errors.New("fhe precompile: allow: unknown handle")
	}
	if metaOwner(meta) != caller {
		return nil, errors.New("fhe precompile: allow: caller is not the handle owner")
	}
	bit, ok := permBit(perm)
	if !ok {
		return nil, fmt.Errorf("fhe precompile: allow: unknown per %d", perm)
	}
	p.grantPerm(db, h, grantee, bit)
	return nil, nil //void return
}
