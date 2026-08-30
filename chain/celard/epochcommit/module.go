package epochcommit

import (
	"encoding/json"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/spf13/cobra"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/cosmos/evm/evmd/epochcommit/keeper"
	"github.com/cosmos/evm/evmd/epochcommit/types"

	"cosmossdk.io/core/appmodule"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
)

// ConsensusVersion defines the current module consensus version.
const ConsensusVersion = 1

var (
	_ module.AppModule      = AppModule{} //nolint:staticcheck // keep for legacy purposes
	_ module.AppModuleBasic = AppModuleBasic{}
	_ module.HasABCIGenesis = AppModule{}
	_ appmodule.AppModule   = AppModule{}
)

// ----------------------------------------------------------------------------
// AppModuleBasic
// ----------------------------------------------------------------------------

type AppModuleBasic struct{}

func NewAppModuleBasic() AppModuleBasic { return AppModuleBasic{} }

func (AppModuleBasic) Name() string { return types.ModuleName }

func (AppModuleBasic) RegisterLegacyAminoCodec(cdc *codec.LegacyAmino) {
	types.RegisterLegacyAminoCodec(cdc)
}

func (AppModuleBasic) ConsensusVersion() uint64 { return ConsensusVersion }

func (AppModuleBasic) RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	types.RegisterInterfaces(reg)
}

func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(types.DefaultGenesisState())
}

func (AppModuleBasic) ValidateGenesis(
	cdc codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage,
) error {
	var gs types.GenesisState
	if err := cdc.UnmarshalJSON(bz, &gs); err != nil {
		return fmt.Errorf("unmarshal %s genesis: %w", types.ModuleName, err)
	}
	return gs.Validate()
}

// No routes and no CLI: the module has no messages and no queries. It is
// written by chain logic and read off-chain through state proofs.
func (AppModuleBasic) RegisterGRPCGatewayRoutes(client.Context, *runtime.ServeMux) {}
func (AppModuleBasic) GetTxCmd() *cobra.Command                                    { return nil }
func (AppModuleBasic) GetQueryCmd() *cobra.Command                                 { return nil }

// ----------------------------------------------------------------------------
// AppModule
// ----------------------------------------------------------------------------

// AppModule for the per-epoch commitment archive.
//
// ⚠️ There is NO RUNTIME WRITE PATH yet. Entries can be established at genesis
// and read through state proofs, and nothing on-chain can record a new one:
// commitments originate off-chain in the KMS ceremony, and the authority that
// should sign a submission is an open question. Registering this module makes
// the archive reachable for reads, NOT complete — see the write-path task doc.
type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

func NewAppModule(k keeper.Keeper) AppModule {
	return AppModule{AppModuleBasic: NewAppModuleBasic(), keeper: k}
}

func (am AppModule) Name() string { return am.AppModuleBasic.Name() }

// RegisterServices registers nothing: no messages, no queries.
func (am AppModule) RegisterServices(module.Configurator) {}

func (am AppModule) InitGenesis(
	ctx sdk.Context, cdc codec.JSONCodec, gs json.RawMessage,
) []abci.ValidatorUpdate {
	var genState types.GenesisState
	cdc.MustUnmarshalJSON(gs, &genState)
	InitGenesis(ctx, am.keeper, &genState)
	return []abci.ValidatorUpdate{}
}

func (am AppModule) ExportGenesis(ctx sdk.Context, cdc codec.JSONCodec) json.RawMessage {
	return cdc.MustMarshalJSON(ExportGenesis(ctx, am.keeper))
}

// IsAppModule implements the appmodule.AppModule interface.
func (AppModule) IsAppModule() {}

// IsOnePerModuleType implements the depinject.OnePerModuleType interface.
func (AppModule) IsOnePerModuleType() {}
