package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
)

// The module has no messages and no service: it is written by chain logic and
// read through state proofs, so there is nothing to register beyond the
// interface the module manager expects.
func RegisterInterfaces(_ cdctypes.InterfaceRegistry) {}

func RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}
