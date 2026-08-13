package fhe

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/testutil"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/x/vm/statedb"
)

// The registry and ACL are written with StateDB.SetState from inside a
// precompile, which has no upstream precedent — every shipped precompile
// writes Cosmos module state through keepers instead. The spike that chose
// this mechanism said plainly that its regression tests are the primary
// evidence it behaves, since there is no upstream test to lean on.
//
// The property under test: when an outer call reverts, handle registrations
// and ACL grants must unwind with it. If they did not, a failed transfer
// could leave a permission behind on an encrypted balance — a confidentiality
// leak produced by an operation that appeared to fail cleanly.
//
// These tests drive the real StateDB and the real journal. A fake store would
// only prove our own simulation of revert, which is not the question.

// mockEVMKeeper is the minimal statedb.Keeper: enough for a real StateDB.
type mockEVMKeeper struct {
	accounts map[common.Address]*statedb.Account
	state    map[common.Address]map[common.Hash]common.Hash
	code     map[common.Hash][]byte
	keys     map[string]storetypes.StoreKey
}

func newMockEVMKeeper() *mockEVMKeeper {
	return &mockEVMKeeper{
		accounts: map[common.Address]*statedb.Account{},
		state:    map[common.Address]map[common.Hash]common.Hash{},
		code:     map[common.Hash][]byte{},
		keys:     map[string]storetypes.StoreKey{},
	}
}

func (m *mockEVMKeeper) GetAccount(_ sdk.Context, addr common.Address) *statedb.Account {
	if acc, ok := m.accounts[addr]; ok {
		return acc
	}
	acc := statedb.NewEmptyAccount()
	m.accounts[addr] = acc
	return acc
}

func (m *mockEVMKeeper) GetState(_ sdk.Context, addr common.Address, key common.Hash) common.Hash {
	return m.state[addr][key]
}

func (m *mockEVMKeeper) GetCode(_ sdk.Context, h common.Hash) []byte { return m.code[h] }

func (m *mockEVMKeeper) GetCodeHash(_ sdk.Context, addr common.Address) common.Hash {
	if acc, ok := m.accounts[addr]; ok {
		return common.BytesToHash(acc.CodeHash)
	}
	return common.Hash{}
}

func (m *mockEVMKeeper) ForEachStorage(_ sdk.Context, addr common.Address,
	cb func(key, value common.Hash) bool) {
	for k, v := range m.state[addr] {
		if !cb(k, v) {
			return
		}
	}
}

func (m *mockEVMKeeper) SetAccount(_ sdk.Context, addr common.Address,
	acc statedb.Account) error {
	m.accounts[addr] = &acc
	return nil
}

func (m *mockEVMKeeper) SetState(_ sdk.Context, addr common.Address,
	key common.Hash, value []byte) {
	if m.state[addr] == nil {
		m.state[addr] = map[common.Hash]common.Hash{}
	}
	m.state[addr][key] = common.BytesToHash(value)
}

func (m *mockEVMKeeper) DeleteState(_ sdk.Context, addr common.Address, key common.Hash) {
	delete(m.state[addr], key)
}

func (m *mockEVMKeeper) SetCode(_ sdk.Context, h []byte, code []byte) {
	m.code[common.BytesToHash(h)] = code
}
func (m *mockEVMKeeper) DeleteCode(_ sdk.Context, h []byte) {
	delete(m.code, common.BytesToHash(h))
}
func (m *mockEVMKeeper) DeleteAccount(_ sdk.Context, addr common.Address) error {
	delete(m.accounts, addr)
	delete(m.state, addr)
	return nil
}
func (m *mockEVMKeeper) KVStoreKeys() map[string]storetypes.StoreKey { return m.keys }

func realStateDB(t *testing.T) *statedb.StateDB {
	t.Helper()
	storeKey := storetypes.NewKVStoreKey("fhe_revert_test")
	tKey := storetypes.NewTransientStoreKey("transient_fhe_revert")
	ctx := testutil.DefaultContext(storeKey, tKey) //nolint:staticcheck
	return statedb.New(ctx, newMockEVMKeeper(), statedb.NewEmptyTxConfig())
}

func TestRevertUnwindsHandleRegistration(t *testing.T) {
	p, db := mustPrecompile(t), realStateDB(t)

	snap := db.Snapshot()
	p.registerHandle(db, handle1, ownerA, 6, false)
	if !metaExists(p.getMeta(db, handle1)) {
		t.Fatal("registration should be visible before revert")
	}

	db.RevertToSnapshot(snap)
	if metaExists(p.getMeta(db, handle1)) {
		t.Fatal("handle registration survived a revert — a failed call would " +
			"leave an owned handle behind")
	}
}

func TestRevertUnwindsACLGrant(t *testing.T) {
	p, db := mustPrecompile(t), realStateDB(t)

	// the handle is registered and committed before the reverted section, so
	// only the grant should disappear
	p.registerHandle(db, handle1, ownerA, 6, false)

	snap := db.Snapshot()
	p.grantPerm(db, handle1, granteeC, permBitReveal)
	if !p.hasPerm(db, handle1, granteeC, permBitReveal) {
		t.Fatal("grant should be visible before revert")
	}

	db.RevertToSnapshot(snap)
	if p.hasPerm(db, handle1, granteeC, permBitReveal) {
		t.Fatal("ACL grant survived a revert — a failed transaction would " +
			"leave a decryption permission on an encrypted value")
	}
	if !metaExists(p.getMeta(db, handle1)) {
		t.Fatal("revert unwound state from before the snapshot")
	}
}

func TestRevertRestoresPreviousPermissionBits(t *testing.T) {
	// Grants are additive, so a revert must restore the prior bitmask rather
	// than clearing the slot: an earlier compute grant must survive the
	// rollback of a later reveal grant.
	p, db := mustPrecompile(t), realStateDB(t)
	p.registerHandle(db, handle1, ownerA, 6, false)
	p.grantPerm(db, handle1, granteeC, permBitCompute)

	snap := db.Snapshot()
	p.grantPerm(db, handle1, granteeC, permBitReveal)
	db.RevertToSnapshot(snap)

	if p.hasPerm(db, handle1, granteeC, permBitReveal) {
		t.Fatal("reveal grant survived revert")
	}
	if !p.hasPerm(db, handle1, granteeC, permBitCompute) {
		t.Fatal("revert destroyed a permission granted before the snapshot")
	}
}
