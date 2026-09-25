package epochcommit

import (
	"context"
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
	_ module.AppModule          = AppModule{} //nolint:staticcheck // keep for legacy purposes
	_ module.AppModuleBasic     = AppModuleBasic{}
	_ module.HasABCIGenesis     = AppModule{}
	_ appmodule.AppModule       = AppModule{}
	_ appmodule.HasBeginBlocker = AppModule{}
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

// RegisterServices wires the write path.
//
// This registered nothing until 2026-09-24, and the comment it carried —
// "no messages, no queries" — was accurate and was the defect: the archive was
// complete, correct and unreachable, written only at genesis while the values
// it holds originate in an off-chain ceremony. A handler that is not registered
// is the same state as a store with no handler.
func (am AppModule) RegisterServices(cfg module.Configurator) {
	types.RegisterMsgServer(cfg.MsgServer(), keeper.NewMsgServerImpl(am.keeper))
}

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

// MaxPrunesPerBlock bounds the sweep so it cannot stall a block. Whatever is
// left is deleted next block, and is already reported as time-barred by the
// bound meanwhile — the bound advances before deletion, so the lag is safe.
const MaxPrunesPerBlock = 100

// BeginBlock advances the retention horizon past epochs whose punishability
// window has closed, and deletes boundedly.
//
// An epoch with no recorded horizon stops the sweep rather than being treated
// as expired: retaining evidence too long costs storage, discarding it early
// destroys punishability and presents as expiry, which exonerates.
func (am AppModule) BeginBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	height := sdkCtx.BlockHeight()
	if height < 0 {
		return nil
	}
	am.keeper.PruneExpired(sdkCtx, uint64(height), MaxPrunesPerBlock)
	return nil
}

// IsAppModule implements the appmodule.AppModule interface.
func (AppModule) IsAppModule() {}

// IsOnePerModuleType implements the depinject.OnePerModuleType interface.
func (AppModule) IsOnePerModuleType() {}
