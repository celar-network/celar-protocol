package fhe

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"

	ethtypes "github.com/ethereum/go-ethereum/core/types"
)

// Op-stream emission — the frozen protocol's §1–§3.
//
// One EVM log per op, from this precompile's account. Logs are the transport
// on purpose: they are journaled (a reverted call frame emits nothing, so the
// stream never carries work from failed transactions), deterministic across
// validators, and covered by the block's receipts commitment, which makes
// "what was asked" provable after the fact.
//
// The precompile executes nothing. It describes, and names the result handle;
// a coprocessor fills the body behind a handle the chain already assigned.

// StreamTopicPreimage is hashed to give topics[0]. Consumers filter on it.
const StreamTopicPreimage = "celar.opstream.v1"

// envelopeVersion is §3's `version` byte. A consumer seeing an unknown value
// MUST halt consumption of the stream rather than skip the event — version
// bumps are governance-gated, so an unrecognised one means the consumer is
// older than the chain, not that the event is optional.
const envelopeVersion byte = 0x01

// streamTopic is topics[0] for every stream event.
var streamTopic = crypto.Keccak256Hash([]byte(StreamTopicPreimage))

// opcodes per §3. Values are frozen: they are consensus-committed in every
// log, so a renumbering is a hard fork rather than a refactor.
var opcodes = map[string]byte{
	VerifyInputMethod:    0x01,
	TrivialEncryptMethod: 0x02,
	AddMethod:            0x10,
	SubMethod:            0x11,
	LeMethod:             0x12,
	LtMethod:             0x13,
	EqMethod:             0x14,
	AndMethod:            0x18,
	OrMethod:             0x19,
	NotMethod:            0x1A,
	SelectMethod:         0x20,
	CastMethod:           0x21,
}

// hcuCost is §3's fhe-dimension weight.
//
// STUB. The real per-class weights are the 2-D fee metering task's, which is
// not started. This emits the flat stub costs the precompile already charges,
// and that is tolerable only because the field is fixed-width: the fee work
// can change the values without changing the wire format or the envelope
// version. It is NOT a fee decision, and should not be read as one.
func hcuCost(methodName string) uint32 {
	switch methodName {
	case VerifyInputMethod, TrivialEncryptMethod:
		return uint32(GasInput)
	default:
		return uint32(GasCompute)
	}
}

// packStreamEvent lays out §3's data section.
//
//	version(1) ‖ opcode(1) ‖ resultType(1) ‖ operandCount(1) ‖
//	operands(32×n) ‖ resultHandle(32) ‖ hcuCost(4) ‖ auxLen(2) ‖ aux
//
// Big-endian for the two numeric fields, matching every other length and
// counter on the wire.
func packStreamEvent(
	opcode byte,
	resultType uint8,
	operands []common.Hash,
	resultHandle common.Hash,
	hcu uint32,
	aux []byte,
) ([]byte, error) {
	if len(operands) > 3 {
		return nil, fmt.Errorf("op-stream: %d operands, schema allows at most 3", len(operands))
	}
	if len(aux) > 0xFFFF {
		return nil, fmt.Errorf("op-stream: aux of %d bytes exceeds the 2-byte length field", len(aux))
	}
	out := make([]byte, 0, 4+32*len(operands)+32+4+2+len(aux))
	out = append(out, envelopeVersion, opcode, resultType, byte(len(operands)))
	for _, o := range operands {
		out = append(out, o.Bytes()...)
	}
	out = append(out, resultHandle.Bytes()...)
	out = binary.BigEndian.AppendUint32(out, hcu)
	out = binary.BigEndian.AppendUint16(out, uint16(len(aux)))
	return append(out, aux...), nil
}

// streamOperands returns the handle arguments in signature order, which is
// what §3 requires: "operand handles, in signature order". Taken from the ABI
// rather than from a per-op table, so adding an op cannot silently disagree
// with its own signature.
func streamOperands(method *abi.Method, argBz []byte) ([]common.Hash, error) {
	args, err := method.Inputs.Unpack(argBz)
	if err != nil {
		return nil, err
	}
	var out []common.Hash
	for _, a := range args {
		if h, ok := a.([32]byte); ok {
			out = append(out, common.BytesToHash(h[:]))
		}
	}
	return out, nil
}

// streamAux builds §3's op-specific tail.
//
// trivialEncrypt carries the public value and its width — the value is public
// by definition, so nothing is disclosed by streaming it. cast carries the
// target width. Compute ops carry nothing: their operands and opcode say
// everything a re-executor needs.
//
// verifyInput is absent deliberately: its aux needs a data-availability
// pointer whose format the frozen text does not give, and which is routed to
// spec. Emitting it with an invented shape would leave the document not
// describing the bytes.
func streamAux(method *abi.Method, argBz []byte) ([]byte, error) {
	args, err := method.Inputs.Unpack(argBz)
	if err != nil {
		return nil, err
	}
	switch method.Name {
	case TrivialEncryptMethod:
		v, ok := args[0].(uint64)
		if !ok {
			return nil, fmt.Errorf("op-stream: trivialEncrypt value is %T, want uint64", args[0])
		}
		k, ok := args[1].(uint8)
		if !ok {
			return nil, fmt.Errorf("op-stream: trivialEncrypt width is %T, want uint8", args[1])
		}
		return append(binary.BigEndian.AppendUint64(nil, v), k), nil
	case CastMethod:
		k, ok := args[1].(uint8)
		if !ok {
			return nil, fmt.Errorf("op-stream: cast width is %T, want uint8", args[1])
		}
		return []byte{k}, nil
	default:
		return nil, nil
	}
}

// emitStreamEvent appends one §3 event for an op the chain has just described.
//
// Skipped in readonly execution: a query is not consensus work, and a log
// emitted from one would put an op in the stream that no block committed to.
func (p Precompile) emitStreamEvent(
	evm *vm.EVM,
	method *abi.Method,
	argBz []byte,
	resultHandle common.Hash,
	resultType uint8,
	readonly bool,
) error {
	if readonly {
		return nil
	}
	opcode, ok := opcodes[method.Name]
	if !ok {
		return fmt.Errorf("op-stream: %s is not a streamed op", method.Name)
	}
	operands, err := streamOperands(method, argBz)
	if err != nil {
		return fmt.Errorf("op-stream: operands for %s: %w", method.Name, err)
	}
	aux, err := streamAux(method, argBz)
	if err != nil {
		return err
	}
	data, err := packStreamEvent(opcode, resultType, operands, resultHandle,
		hcuCost(method.Name), aux)
	if err != nil {
		return err
	}
	evm.StateDB.AddLog(&ethtypes.Log{
		Address: common.HexToAddress(CelarFHEPrecompileAddress),
		Topics:  []common.Hash{streamTopic},
		Data:    data,
	})
	return nil
}

// StreamEvent is a decoded §3 event.
type StreamEvent struct {
	Version      byte
	Opcode       byte
	ResultType   uint8
	Operands     []common.Hash
	ResultHandle common.Hash
	HCUCost      uint32
	Aux          []byte
}

// DecodeStreamEvent parses §3's data section.
//
// Kept in the precompile rather than only in tests so the bytes are read back
// by something other than the writer, and so the consumer side has one
// definition to build against rather than reimplementing the layout.
//
// An unknown version is an ERROR, not a skip: §3 says a consumer seeing one
// MUST halt consumption. A newer envelope means the reader is older than the
// chain, and continuing would mean interpreting later events under an
// assumption already known to be wrong.
func DecodeStreamEvent(data []byte) (StreamEvent, error) {
	var e StreamEvent
	if len(data) < 4 {
		return e, fmt.Errorf("op-stream: event of %d bytes is shorter than the header", len(data))
	}
	e.Version, e.Opcode, e.ResultType = data[0], data[1], data[2]
	if e.Version != envelopeVersion {
		return e, fmt.Errorf(
			"op-stream: envelope version %#x is not %#x — halt consumption; "+
				"this reader is older than the chain", e.Version, envelopeVersion)
	}
	count := int(data[3])
	if count > 3 {
		return e, fmt.Errorf("op-stream: operandCount %d exceeds the schema's 3", count)
	}
	off := 4
	need := off + 32*count + 32 + 4 + 2
	if len(data) < need {
		return e, fmt.Errorf("op-stream: event of %d bytes, need %d for %d operands",
			len(data), need, count)
	}
	for i := 0; i < count; i++ {
		e.Operands = append(e.Operands, common.BytesToHash(data[off:off+32]))
		off += 32
	}
	e.ResultHandle = common.BytesToHash(data[off : off+32])
	off += 32
	e.HCUCost = binary.BigEndian.Uint32(data[off : off+4])
	off += 4
	auxLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if len(data)-off != auxLen {
		return e, fmt.Errorf("op-stream: auxLen says %d, %d bytes remain",
			auxLen, len(data)-off)
	}
	e.Aux = data[off:]
	return e, nil
}
