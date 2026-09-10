package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

// RegisterInterfaces makes the module's messages decodable.
//
// Unlike the commitment archive, this module accepts messages: evidence and
// attestations arrive as transactions rather than being written by chain
// logic. So the message type has to be registered as an implementation of the
// message interface, and the service description registered so the router can
// find the handler.
func RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	reg.RegisterImplementations((*sdk.Msg)(nil), &MsgSubmitAttestation{})
	msgservice.RegisterMsgServiceDesc(reg, &_Msg_serviceDesc)
}

// No amino: nothing here is signed with the legacy encoding, and registering
// a type there that nothing uses invites someone to sign with it.
func RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}
