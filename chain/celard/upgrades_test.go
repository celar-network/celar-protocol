package evmd

import (
	"sort"
	"testing"

	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	precisebankkeeper "github.com/cosmos/evm/evmd/precisebank/keeper"
)

// Every store the app mounts must be accounted for as either present at genesis
// or added by an upgrade. Adding a module and forgetting the second is not
// visible until a chain tries to restart on the new binary, months later and on
// someone else's machine, as a store version mismatch that no flag skips.
//
// This test is the moment that mistake becomes visible instead.
func TestEveryMountedStoreIsAccountedFor(t *testing.T) {
	mounted := kvStoreKeyNames()
	accounted := append(storesAtGenesis(), storesAddedByUpgrade()...)

	sort.Strings(mounted)
	sort.Strings(accounted)

	if len(mounted) != len(accounted) {
		t.Fatalf("mounted %d stores, accounted for %d", len(mounted), len(accounted))
	}
	for i := range mounted {
		if mounted[i] != accounted[i] {
			t.Fatalf("store %q is mounted but not accounted for as genesis-era "+
				"or upgrade-added", mounted[i])
		}
	}

	seen := map[string]bool{}
	for _, s := range mounted {
		if seen[s] {
			t.Fatalf("store %q listed twice", s)
		}
		seen[s] = true
	}
}

// The upgrade must actually carry the stores that are not at genesis. An empty
// Added list is what upstream's sample upgrade ships with, and it is silently
// useless: the upgrade runs, reports success, and the chain still cannot load.
// The genesis-era list is frozen here. Moving a store between the two lists
// changes what an upgrade does to a live chain — adding a store that already
// exists, or failing to add one that does not — and neither shows up until a
// restart on a real chain. A literal copy is the only thing that makes such a
// move visible in review.
func TestGenesisEraStoresAreFrozen(t *testing.T) {
	frozen := []string{
		"acc", "bank", "staking", "mint", "distribution", "slashing",
		"gov", "consensus", "upgrade", "feegrant", "evidence", "authz",
		"ibc", "transfer", "evm", "feemarket", "erc20", "precisebank",
	}
	got := storesAtGenesis()
	if len(got) != len(frozen) {
		t.Fatalf("genesis-era stores: %d, frozen list has %d: %v vs %v",
			len(got), len(frozen), got, frozen)
	}
	for i := range got {
		if got[i] != frozen[i] {
			t.Fatalf("genesis-era store %d is %q, frozen list says %q. "+
				"If a module really did exist at genesis, update the frozen "+
				"list in the same commit and say why", i, got[i], frozen[i])
		}
	}
}

func TestUpgradeAddsTheNonGenesisStores(t *testing.T) {
	if len(storesAddedByUpgrade()) == 0 {
		t.Fatal("no stores added by the upgrade: either every module predates " +
			"genesis, or this list was left empty like the sample it replaced")
	}
	genesis := map[string]bool{}
	for _, s := range storesAtGenesis() {
		genesis[s] = true
	}
	for _, s := range storesAddedByUpgrade() {
		if genesis[s] {
			t.Fatalf("store %q is claimed both at genesis and as added", s)
		}
	}
}

// The ERC20 precompile's native-coin send path cannot work on this chain, and
// this test exists so that stays a decision rather than a surprise.
//
// Upstream's erc20 message server type-switches on the bank keeper and accepts
// only bankkeeper.BaseKeeper or a pointer to it, erroring on anything else.
// app.go hands erc20 the PRECISEBANK keeper, deliberately, because that is what
// gives the EVM eighteen decimals over a nine-decimal bank denom. So every
// native-coin transfer through that precompile reverts with "invalid keeper
// type".
//
// It is latent rather than live: nothing activates that precompile and no token
// pair is registered, so the path is unreachable today. It becomes reachable the
// first time someone wants a wrapped-native or IBC-ERC20 surface.
//
// The decision recorded against this is: document the absence and enforce it,
// rather than fork the chain's core EVM dependency for a surface nothing needs
// yet, and rather than hand erc20 the base bank keeper — which would compile,
// pass, and move nine-decimal units where the EVM believes eighteen.
//
// ⚠️ WHAT THIS TEST DOES AND DOES NOT DO. It pins the type incompatibility, so
// it fails if upstream widens the accepted types or if precisebank starts
// satisfying them — either of which means the decision above can be revisited.
// It does NOT prove the wiring is still precisebank: that lives in app.go and a
// test in this package cannot read it without constructing the app. If someone
// switches erc20 to the base bank keeper, this test keeps passing and the
// decimals break silently. That gap is named here rather than papered over.
func TestErc20PrecompileStillCannotTakePrecisebank(t *testing.T) {
	var k any = precisebankkeeper.Keeper{}
	switch k.(type) {
	case bankkeeper.BaseKeeper, *bankkeeper.BaseKeeper:
		t.Fatal("precisebank now satisfies the erc20 message server's type " +
			"switch: the native-coin path may be enableable, and the decision " +
			"to document its absence should be revisited rather than inherited")
	}
}
