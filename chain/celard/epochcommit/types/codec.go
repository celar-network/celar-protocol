package types

import (
	"github.com/cosmos/cosmos-sdk/codec"
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
)

// RegisterInterfaces registers the module's one message.
//
// It registered nothing until 2026-09-24, and the comment saying so was
// correct at the time: the archive was genesis-written by design while the
// runtime write path's authority was undecided. Now that the path exists, the
// message has to be registered here or a transaction carrying it cannot be
// decoded — the failure would surface as an unroutable message rather than as
// anything naming this file.
func RegisterInterfaces(reg cdctypes.InterfaceRegistry) {
	reg.RegisterImplementations((*sdk.Msg)(nil), &MsgSubmitEpochCommitments{})
	msgservice.RegisterMsgServiceDesc(reg, &_Msg_serviceDesc)
}

// No amino: nothing here is signed with the legacy encoding, and registering
// a type there that nothing uses invites someone to sign with it.
func RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}
