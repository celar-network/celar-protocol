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

// Precompile implements the Celar FHE precompile stub.
//
// Compute ops (add/sub/le/lt/eq/and/or/not/select/cast) and trivialEncrypt
// are STATELESS: the returned handle is a deterministic hash of the inputs.
// They never touch RunNativeAction, so they never count against
// MaxPrecompileCalls.
//
// allow / requestReencrypt / requestReveal are STATEFUL: they run through
// RunNativeAction (the journaled path) and emit cosmos events. Real ACL
// storage is a separate task; real KMS semantics live in the KMS.
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
		h := p.deriveAdmissionHandle(method, argBz, evm.Origin)
		p.registerHandle(evm.StateDB, h, contract.Caller(),
			KTypeUnknown, readonly)
		return method.Outputs.Pack(h)

	case TrivialEncryptMethod, AddMethod, SubMethod, LeMethod, LtMethod,
		EqMethod, AndMethod, OrMethod, NotMethod, SelectMethod, CastMethod:
		if err := p.checkComputeAccess(evm.StateDB, contract.Caller(), method, argBz, readonly); err != nil {
			return nil, err
		}
		h := p.deriveHandle(method, argBz)
		ktype := p.resultKType(evm.StateDB, method, argBz)
		p.registerHandle(evm.StateDB, h, contract.Caller(), ktype, readonly)
		// The op-stream event is what a coprocessor executes from: the
		// precompile describes the work and names its result handle, and
		// nothing computes here. Emitted after registration so a consumer
		// never sees a handle the chain has not yet recorded.
		if err := p.emitStreamEvent(evm, method, argBz, h, ktype, readonly); err != nil {
			return nil, err
		}
		return method.Outputs.Pack(h)

	// ---- stateful: ACL + KMS gateway (journaled path) --------------------
	case AllowMethod:
		if readonly {
			return nil, vm.ErrWriteProtection
		}
		return p.runAllow(evm.StateDB, contract.Caller(), method, argBz)

	// ---- stateful : KMS gateway (ACL-guarded, journaled) ------------
	case RequestReencryptMethod, RequestRevealMethod:
		if readonly {
			return nil, vm.ErrWriteProtection
		}
		if err := p.checkServable(evm.StateDB, contract.Caller(),
			method.Name, argBz); err != nil {
			return nil, err
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

// deriveAdmissionHandle computes the handle for an admitted input:
//
//	handle = keccak256(domainTag || methodName || submitter || rawArgs)
//
// The submitter is the transaction origin — the same principal the
// corrected input-proof tuple binds, and deliberately not the immediate
// caller, which is usually a contract and identical for all its users.
//
// Without it, two parties supplying the same (ciphertext, proof) derive
// the same handle, and first-writer-wins hands ownership to whoever lands
// first: the front-running path, demonstrated in frontrun_test.go.
//
// Compute ops deliberately do NOT bind a principal. Equal values reached
// by identical traces therefore still share a handle, which is a
// confidentiality property tracked separately — binding compute results
// would change what every coprocessor must reproduce.
//
// Note on the concatenation: the preimage carries no length prefixes, so
// it is unambiguous only because no method name is a prefix of another.
// That holds for the current set; a new method must preserve it.
func (p Precompile) deriveAdmissionHandle(
	method *abi.Method,
	argBz []byte,
	submitter common.Address,
) common.Hash {
	preimage := make([]byte, 0,
		len(domainTag)+len(method.Name)+common.AddressLength+len(argBz))
	preimage = append(preimage, []byte(domainTag)...)
	preimage = append(preimage, []byte(method.Name)...)
	preimage = append(preimage, submitter.Bytes()...)
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
	db stateStore,
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
			return ktypeForWidth(k)
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
	db stateStore,
	argBz []byte,
	idx int,
) uint8 {
	off := idx * 32
	if len(argBz) < off+32 {
		return KTypeUnknown
	}
	meta := p.getMeta(db, common.BytesToHash(argBz[off:off+32]))
	if !metaExists(meta) {
		return KTypeUnknown
	}
	return metaKType(meta)
}

// runAllow enforces the owner-only write rule and records the grant:
// only the account that created h(per the handle registry) may add ACL
// entries for it. Grants are additive perm bits in ach[h][grantee].
func (p Precompile) runAllow(
	db stateStore,
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
	if !metaExists(meta) {
		return nil, errors.New("fhe precompile: allow: unknown handle")
	}
	if metaOwner(meta) != caller {
		return nil, errors.New("fhe precompile: allow: caller is not the handle owner")
	}
	bit, ok := permBit(perm)
	if !ok {
		return nil, fmt.Errorf("fhe precompile: allow: unknown perm %d", perm)
	}
	p.grantPerm(db, h, grantee, bit)
	return nil, nil //void return
}

// checkServable mirrors the KMS servability predicate at request time:
// re-encryption is servable for the handle's owner or a holder of the
// reencrypt-to-self grant; reveal only for a holder of the reveal grant
// (explicit per-handle, no wildcards). The handle is the first static
// argument of both request methods.
func (p Precompile) checkServable(
	db stateStore,
	caller common.Address,
	methodName string,
	argBz []byte,
) error {
	if len(argBz) < 32 {
		return errors.New("fhe precompile: request: missing handle arg")
	}
	h := common.BytesToHash((argBz[:32]))
	meta := p.getMeta(db, h)
	if !metaExists(meta) {
		return errors.New("fhe precompile: request: unknown handle")
	}
	switch methodName {
	case RequestReencryptMethod:
		if metaOwner(meta) == caller ||
			p.hasPerm(db, h, caller, permBitReencryptToSelf) {
			return nil
		}
		return errors.New("fhe precompile: reencrypt not authorized for caller")
	case RequestRevealMethod:
		if p.hasPerm(db, h, caller, permBitReveal) {
			return nil
		}
		return errors.New("fhe precompile: reveal not granted for this handle")
	}
	return nil
}

// checkComputeAcess enforces the frozen ABI's compute permission: a
// caller may operate on a handle only if it owns that handle of holds
// a comoute grant on it
//
// Without this the access-control list is decorative. Handles are
// public - they appear in calldata, events and contract storage - so
// anyone could compute a predicate of somebody else's encrypted value,
// take ownership of the result because results are registered to their
// creator, grant themselves reveal on it, and have the committee
// disclose the answer. Around sixty-four such queries recover a
// balance exactly.
//
// Skipped in read-only contexts fo the same reason registration is:
// a static call commits nothing, handles derived within it are never
// registered, and enforcing here would break eth_call simulation of
// multi-step flows.
func (p Precompile) checkComputeAccess(
	db stateStore,
	caller common.Address,
	method *abi.Method,
	argBz []byte,
	readonly bool,
) error {
	if readonly {
		return nil
	}
	for i, in := range method.Inputs {
		if in.Type.T != abi.FixedBytesTy || in.Type.Size != 32 {
			continue // not a handle: a widht, a value, an address
		}
		off := i * 32
		if len(argBz) < off+32 {
			return errors.New("fhe precompile: truncated operand")
		}
		h := common.BytesToHash(argBz[off : off+32])
		meta := p.getMeta(db, h)
		if !metaExists(meta) {
			return fmt.Errorf("fhe precompile: unknown handle %s", h.Hex())
		}
		if metaOwner(meta) == caller {
			continue
		}
		if p.hasPerm(db, h, caller, permBitCompute) {
			continue
		}
		return fmt.Errorf("fhe precompile: caller lacks compute permission on %s", h.Hex())
	}
	return nil
}
