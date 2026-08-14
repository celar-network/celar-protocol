package fhe

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// stateStore is the narrow slice of vm.StateDB the registry and ACL need.
// The real EVM StateDB satisfies it; tests use a map-backed fake
type stateStore interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash) common.Hash
}

// EVM storage layout of the precompile account -  see STORAGE-LAYOUT.md.
// Solidity-compatible slots:
//
// slot 0: layout version
// slot 1: base of mapping(bytes32 handle => bytes32 packedMeta)
// slot2: base of mapping(bytes32 handle => mapping(address => uint256 perms))
const (
	baseSlotHandleMeta = 1
	baseSlotACL        = 2
)

// Plaintext type tags stored in handleMeta[h], and emitted as the op-steams
// `resultType` field once A6 lands.
//
// Log-coded rather than raw bit width: euint -> 3 -- euint64 -> 6, i.e.
// log2(bits). Compact, leaves room for wider types, and matches
// STORAGE-LAYOUT.md and the op-sream protocol. Storing the raw width here
// was a defect - the specification, the tests and this code disagreed three
// ways until the op-stream review caught it. at which point the value became
// a wire format rather than private bookkeeping

const (
	KTypeEbool   uint8 = 0
	kTypeEuint8  uint8 = 3
	kTypeEuint16 uint8 = 4
	kTypeEuint32 uint8 = 5
	kTypeEuint64 uint8 = 6
	KTypeUnknown uint8 = 0xFF
)

func ktypeForWidth(bits uint8) uint8 {
	switch bits {
	case 8:
		return kTypeEuint8
	case 16:
		return kTypeEuint16
	case 32:
		return kTypeEuint32
	case 64:
		return kTypeEuint64
	}
	return KTypeUnknown
}

// metaSlot returns the lsot of handleMeta[h]:
// keccah256(h || uint256(baseSlotHandleMeta)).
func metaSlot(h common.Hash) common.Hash {
	var base common.Hash
	base[31] = baseSlotHandleMeta
	return crypto.Keccak256Hash(h.Bytes(), base.Bytes())
}

// aclSlot returns the slot of acl[h][grantee]:
// keccak256(pad32(grantee) || keccak256(h || uint256(baseSlotACL))).
func aclSlot(h common.Hash, grantee common.Address) common.Hash {
	var base common.Hash
	base[31] = baseSlotACL
	inner := crypto.Keccak256Hash(h.Bytes(), base.Bytes())
	var g common.Hash
	copy(g[12:], grantee.Bytes())
	return crypto.Keccak256Hash(g.Bytes(), inner.Bytes())
}

// packMeta packs (owner, ktype, exists=1) into one storage word:
// bytes 0-19 owner, bytes 20 ktype, byte 21 flags (bit0 = exits)
func packMeta(owner common.Address, ktype uint8) common.Hash {
	var w common.Hash
	copy(w[:20], owner.Bytes())
	w[20] = ktype
	w[21] = 0x01
	return w
}

func metaExists(w common.Hash) bool { return w[21]&0x01 == 1 }

func metaOwner(w common.Hash) common.Address {
	var a common.Address
	copy(a[:], w[:20])
	return a
}

func metaKType(w common.Hash) uint8 { return w[20] }

// getMeta read handleMeta[h] from the precompile's storage.
func (p Precompile) getMeta(db stateStore, h common.Hash) common.Hash {
	return db.GetState(p.ContractAddress, metaSlot(h))
}

// registerHandle records (owner, ktype, exists) for a newly create handle.
// First writer winds: stub handles are deterministic, so identical (op, args)
// from different callers derive the same handle - re-registration must not
// transfer ownership. No-op in readonly (static-call) contexts: SetState
// would bypass the EVM's own write protection there.
func (p Precompile) registerHandle(
	db stateStore,
	h common.Hash,
	owner common.Address,
	ktype uint8,
	readonly bool,
) {
	if readonly {
		return
	}
	if metaExists(p.getMeta(db, h)) {
		return
	}
	db.SetState(p.ContractAddress, metaSlot(h), packMeta(owner, ktype))
}

// Permission bits stored in acl[h][grantee] (low-order byte of the word).
const (
	permBitCompute         byte = 0x01
	permBitReencryptToSelf byte = 0x02
	permBitReveal          byte = 0x04
)

// permBit maps an ABI perm value (0/1/2) to its storage bit.
func permBit(perm uint8) (byte, bool) {
	switch perm {
	case PermCompute:
		return permBitCompute, true
	case PermReencryptToSelf:
		return permBitReencryptToSelf, true
	case PermReveal:
		return permBitReveal, true
	}
	return 0, false
}

// grantPerm ORs a permission bit into acl[h][grantee]. Additive only —
// revocation is not in the frozen ABI.
func (p Precompile) grantPerm(
	db stateStore,
	h common.Hash,
	grantee common.Address,
	bit byte,
) {
	slot := aclSlot(h, grantee)
	word := db.GetState(p.ContractAddress, slot)
	word[31] |= bit
	db.SetState(p.ContractAddress, slot, word)
}

// hasPerm reports whether acl[h][addr] carries the given permission bit.
func (p Precompile) hasPerm(
	db stateStore,
	h common.Hash,
	addr common.Address,
	bit byte,
) bool {
	return db.GetState(p.ContractAddress, aclSlot(h, addr))[31]&bit != 0
}
