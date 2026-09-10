package keeper

import (
	"context"

	"github.com/cosmos/evm/evmd/fraudevidence/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

type msgServer struct {
	k Keeper
}

// NewMsgServerImpl returns the message service backed by this keeper.
func NewMsgServerImpl(k Keeper) types.MsgServer {
	return &msgServer{k: k}
}

var _ types.MsgServer = (*msgServer)(nil)

// SubmitAttestation records a coprocessor's attestation for one stream
// position.
//
// The signer is a relayer, not an authority: the attestation carries its own
// coprocessor identity and its own signature over the pinned preimage, so who
// sent it does not affect what is recorded. A coprocessor that cannot reach
// the chain should not thereby be unable to have its work recorded.
//
// Which puts the weight on the store's refusal of conflicting claims. Anyone
// may submit; nobody may replace. An identical resubmission reports that it
// was already there rather than erroring, because at-least-once delivery and
// permissionless relaying make duplicates ordinary - and a relayer that cannot
// distinguish "stored" from "already stored" either retries forever or reads
// success as failure.
func (m msgServer) SubmitAttestation(
	goCtx context.Context,
	msg *types.MsgSubmitAttestation,
) (*types.MsgSubmitAttestationResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	existed, err := m.k.RecordAttestation(ctx, msg.Attestation)
	if err != nil {
		return nil, err
	}
	return &types.MsgSubmitAttestationResponse{AlreadyRecorded: existed}, nil
}
