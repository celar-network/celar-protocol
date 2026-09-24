//go:build test

package keeper_test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/cosmos/evm/evmd/fraudevidence/keeper"
	"github.com/cosmos/evm/evmd/fraudevidence/types"
)

func signedAttestation(t *testing.T, key *ecdsa.PrivateKey) types.Attestation {
	t.Helper()
	a := types.Attestation{
		Height: 42, TxIndex: 1, LogIndex: 2,
		ResultHandle: make([]byte, 32),
		CtDigest:     make([]byte, 32),
		EnvVersion:   types.EnvDigestAndSignature,
	}
	for i := range a.ResultHandle {
		a.ResultHandle[i] = 0xAB
		a.CtDigest[i] = 0xCD
	}
	p := types.AttestationPreimage(testChainID, a.Height, a.TxIndex, a.LogIndex,
		[32]byte(a.ResultHandle), [32]byte(a.CtDigest))
	sig, err := crypto.Sign(p[:], key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	a.Signature = sig
	a.CoprocessorId = crypto.PubkeyToAddress(key.PublicKey).Bytes()
	return a
}

func TestHandlerAcceptsASignedAttestationAndIsIdempotent(t *testing.T) {
	k, ctx := newKeeper(t)
	srv := keeper.NewMsgServerImpl(k)
	key, _ := crypto.GenerateKey()
	a := signedAttestation(t, key)

	res, err := srv.SubmitAttestation(ctx, &types.MsgSubmitAttestation{Attestation: a})
	if err != nil {
		t.Fatalf("a correctly signed attestation was rejected: %v", err)
	}
	if res.AlreadyRecorded {
		t.Fatal("first submission reported as already recorded")
	}

	// Permissionless relaying and at-least-once delivery make duplicates
	// ordinary, so a resubmission reports rather than errors.
	res, err = srv.SubmitAttestation(ctx, &types.MsgSubmitAttestation{Attestation: a})
	if err != nil {
		t.Fatalf("resubmission errored: %v", err)
	}
	if !res.AlreadyRecorded {
		t.Fatal("resubmission did not report that it was already recorded")
	}
}

// The property the whole change exists for: a rejected attestation must leave
// the store untouched. An endpoint that validates and then writes anyway is
// indistinguishable from one that does not validate.
func TestRejectedAttestationIsNotRecorded(t *testing.T) {
	k, ctx := newKeeper(t)
	srv := keeper.NewMsgServerImpl(k)
	signer, _ := crypto.GenerateKey()
	impostor, _ := crypto.GenerateKey()

	a := signedAttestation(t, signer)
	a.CoprocessorId = crypto.PubkeyToAddress(impostor.PublicKey).Bytes()

	if _, err := srv.SubmitAttestation(ctx,
		&types.MsgSubmitAttestation{Attestation: a}); err == nil {
		t.Fatal("an attestation claiming another identity was accepted")
	}

	if _, found, err := k.Attestation(ctx, a.Height, a.TxIndex, a.LogIndex); err != nil {
		t.Fatalf("read back: %v", err)
	} else if found {
		t.Fatal("a rejected attestation was written to the store anyway")
	}
}
