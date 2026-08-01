package fhe

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// fakeStore is a flat map-backed stateStore keyed by address+slot.
type fakeStore struct{ m map[string]common.Hash }

func newFakeStore() *fakeStore { return &fakeStore{m: map[string]common.Hash{}} }

func fsKey(a common.Address, k common.Hash) string {
	return a.Hex() + ":" + k.Hex()
}

func (f *fakeStore) GetState(a common.Address, k common.Hash) common.Hash {
	return f.m[fsKey(a, k)]
}

func (f *fakeStore) SetState(a common.Address, k, v common.Hash) common.Hash {
	key := fsKey(a, k)
	prev := f.m[key]
	f.m[key] = v
	return prev
}

func mustPrecompile(t *testing.T) *Precompile {
	t.Helper()
	p, err := NewPrecompile()
	if err != nil {
		t.Fatalf("NewPrecompile: %v", err)
	}
	return p
}

func wantErr(t *testing.T, err error, frag string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), frag) {
		t.Fatalf("want error containing %q, got %v", frag, err)
	}
}

var (
	ownerA    = common.HexToAddress("0xA000000000000000000000000000000000000001")
	strangerB = common.HexToAddress("0xB000000000000000000000000000000000000002")
	granteeC  = common.HexToAddress("0xC000000000000000000000000000000000000003")
	handle1   = common.HexToHash("0x01")
)

// TestFakeStoreRoundTrip isolates the test double from the logic under test.
func TestFakeStoreRoundTrip(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	slot := metaSlot(handle1)
	want := packMeta(ownerA, 6)
	db.SetState(p.ContractAddress, slot, want)
	if got := db.GetState(p.ContractAddress, slot); got != want {
		t.Fatalf("store round-trip failed: got %s want %s",
			got.Hex(), want.Hex())
	}
	if got := p.getMeta(db, handle1); got != want {
		t.Fatalf("getMeta mismatch: got %s want %s", got.Hex(), want.Hex())
	}
}

func TestRegisterFirstWriterWins(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	p.registerHandle(db, handle1, ownerA, 6, false)
	if meta := p.getMeta(db, handle1); !metaExists(meta) {
		t.Fatalf("registration did not persist: %s", meta.Hex())
	}
	p.registerHandle(db, handle1, strangerB, 6, false) // must not re-own
	meta := p.getMeta(db, handle1)
	if metaOwner(meta) != ownerA {
		t.Fatalf("ownership hijacked: owner=%s", metaOwner(meta).Hex())
	}
	if metaKType(meta) != 6 {
		t.Fatalf("ktype lost: %d", metaKType(meta))
	}
}

func TestRegisterReadonlySkips(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	p.registerHandle(db, handle1, ownerA, 6, true)
	if metaExists(p.getMeta(db, handle1)) {
		t.Fatal("readonly context must not write")
	}
}

func TestAllowOwnerOnly(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	method := p.abi.Methods[AllowMethod]
	packed, err := p.abi.Pack(AllowMethod,
		[32]byte(handle1), granteeC, PermReencryptToSelf)
	if err != nil {
		t.Fatalf("pack allow: %v", err)
	}
	args := packed[4:]

	_, err = p.runAllow(db, ownerA, &method, args)
	wantErr(t, err, "unknown handle")

	p.registerHandle(db, handle1, ownerA, 6, false)

	_, err = p.runAllow(db, strangerB, &method, args)
	wantErr(t, err, "not the handle owner")

	if _, err = p.runAllow(db, ownerA, &method, args); err != nil {
		t.Fatalf("owner grant failed: %v", err)
	}
	if !p.hasPerm(db, handle1, granteeC, permBitReencryptToSelf) {
		t.Fatal("grant bit not set")
	}
	if p.hasPerm(db, handle1, granteeC, permBitReveal) {
		t.Fatal("unrelated permission leaked")
	}

	badPacked, err := p.abi.Pack(AllowMethod,
		[32]byte(handle1), granteeC, uint8(9))
	if err != nil {
		t.Fatalf("pack bad allow: %v", err)
	}
	_, err = p.runAllow(db, ownerA, &method, badPacked[4:])
	wantErr(t, err, "unknown perm")
}

func TestServability(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	// checkServable reads only the leading 32-byte handle argument.
	args := handle1.Bytes()

	wantErr(t, p.checkServable(db, ownerA, RequestReencryptMethod, args),
		"unknown handle")

	p.registerHandle(db, handle1, ownerA, 6, false)

	if err := p.checkServable(db, ownerA,
		RequestReencryptMethod, args); err != nil {
		t.Fatalf("owner reencrypt should be servable: %v", err)
	}
	wantErr(t, p.checkServable(db, strangerB,
		RequestReencryptMethod, args), "not authorized")
	p.grantPerm(db, handle1, strangerB, permBitReencryptToSelf)
	if err := p.checkServable(db, strangerB,
		RequestReencryptMethod, args); err != nil {
		t.Fatalf("granted reencrypt: %v", err)
	}

	// reveal needs the explicit per-handle grant, even for the owner
	wantErr(t, p.checkServable(db, ownerA, RequestRevealMethod, args),
		"not granted")
	p.grantPerm(db, handle1, granteeC, permBitReveal)
	if err := p.checkServable(db, granteeC,
		RequestRevealMethod, args); err != nil {
		t.Fatalf("granted reveal: %v", err)
	}
}
