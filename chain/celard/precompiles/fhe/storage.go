package fhe

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
)

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

// Plaintext type tags stored in handleMeta[h]:
const (
	KTypeEbool   uint8 = 0
	KTypeUnknown uint8 = 0xFF
)

// metaSlot returns the lsot of handleMeta[h]:
// keccah256(h || uint256(baseSlotHandleMeta)).
func MetaSlot(h common.Hash) common.Hash {
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

func metaExist(w common.Hash) bool { return w[21]&0x01 == 1 }

func metaOwner(w common.Hash) common.Address {
	var a common.Address
	copy(a[:], w[:20])
	return a
}

func metaKType(w common.Hash) uint8 { return w[20] }

// getMeta read handleMeta[h] from the precompile's storage.
func (p Precompile) getMeta(db vm.StateDB, h common.Hash) common.Hash {
	return db.GetState(p.ContractAddress, MetaSlot(h))
}

// registerHandle records (owner, ktype, exists) for a newly create handle.
// First writer winds: stub handles are deterministic, so identical (op, args)
// from different callers derive the same handle - re-registration must not
// transfer ownership. No-op in readonly (static-call) contexts: SetState
// would bypass the EVM's own write protection there.
func (p Precompile) registerHandle(
	db vm.StateDB,
	h common.Hash,
	owner common.Address,
	ktype uint8,
	readonly bool,
) {
	if readonly {
		return
	}
	if metaExist(p.getMeta(db, h)) {
		db.SetState(p.ContractAddress, MetaSlot(h), packMeta(owner, ktype))
	}
}
