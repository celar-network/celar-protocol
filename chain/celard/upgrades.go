package evmd

import (
	"context"

	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	consensusparamtypes "github.com/cosmos/cosmos-sdk/x/consensus/types"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	evidencetypes "github.com/cosmos/cosmos-sdk/x/evidence/types"
	"github.com/cosmos/cosmos-sdk/x/feegrant"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	minttypes "github.com/cosmos/cosmos-sdk/x/mint/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"
	epochcommittypes "github.com/cosmos/evm/evmd/epochcommit/types"
	fraudevidencetypes "github.com/cosmos/evm/evmd/fraudevidence/types"
	erc20types "github.com/cosmos/evm/x/erc20/types"
	feemarkettypes "github.com/cosmos/evm/x/feemarket/types"
	precisebanktypes "github.com/cosmos/evm/evmd/precisebank/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	ibctransfertypes "github.com/cosmos/ibc-go/v11/modules/apps/transfer/types"
	ibcexported "github.com/cosmos/ibc-go/v11/modules/core/exported"
)

// UpgradeName is the on-chain upgrade that brings a running chain onto this
// code. It is named rather than versioned because what it does is add stores,
// and the store list below is the part that matters to an operator.
//
// A chain cannot reach a module whose store its multistore lacks. Restarting on
// a binary with an unlisted store fails at load with
//
//	version of store <name> mismatch root store's version; expected N got 0
//
// and the node exits. There is no flag that skips it. That failure is how a
// devnet came to run a binary five weeks behind its tree for a month, which was
// then diagnosed as a missing protocol feature.
const UpgradeName = "celar-1-epochcommit-fraudevidence"

// storesAddedByUpgrade are the stores this upgrade introduces: modules added
// after a chain's genesis. Anything listed here is unreachable by an older
// chain until the upgrade runs.
func storesAddedByUpgrade() []string {
	return []string{
		epochcommittypes.StoreKey,
		fraudevidencetypes.StoreKey,
	}
}

// storesAtGenesis are the stores a chain has from its own genesis. Kept
// separate from the added list so that the two together must account for every
// store the app mounts — which is what upgrades_test.go checks, and what makes
// the next module addition fail a test rather than a node restart.
func storesAtGenesis() []string {
	return []string{
		authtypes.StoreKey, banktypes.StoreKey, stakingtypes.StoreKey,
		minttypes.StoreKey, distrtypes.StoreKey, slashingtypes.StoreKey,
		govtypes.StoreKey, consensusparamtypes.StoreKey,
		upgradetypes.StoreKey, feegrant.StoreKey, evidencetypes.StoreKey,
		authzkeeper.StoreKey,
		// ibc keys
		ibcexported.StoreKey, ibctransfertypes.StoreKey,
		// Cosmos EVM store keys
		evmtypes.StoreKey, feemarkettypes.StoreKey, erc20types.StoreKey,
		// precisebank store key (fractional balances + remainder)
		precisebanktypes.StoreKey,
	}
}

// kvStoreKeyNames is every KV store the app mounts. app.go builds its store
// keys from this, so a store cannot be mounted without appearing in one of the
// two lists above.
//
// The epochcommit store name is part of the proof path the KMS verifier
// checks, so it is not free to rename.
func kvStoreKeyNames() []string {
	return append(storesAtGenesis(), storesAddedByUpgrade()...)
}

func (app EVMD) RegisterUpgradeHandlers() {
	app.UpgradeKeeper.SetUpgradeHandler(
		UpgradeName,
		func(ctx context.Context, _ upgradetypes.Plan, fromVM module.VersionMap) (module.VersionMap, error) {
			return app.ModuleManager.RunMigrations(ctx, app.Configurator(), fromVM)
		},
	)

	upgradeInfo, err := app.UpgradeKeeper.ReadUpgradeInfoFromDisk()
	if err != nil {
		panic(err)
	}

	if upgradeInfo.Name == UpgradeName && !app.UpgradeKeeper.IsSkipHeight(upgradeInfo.Height) {
		storeUpgrades := storetypes.StoreUpgrades{
			Added: storesAddedByUpgrade(),
		}
		app.SetStoreLoader(upgradetypes.UpgradeStoreLoader(upgradeInfo.Height, &storeUpgrades))
	}
}
