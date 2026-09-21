//go:build test

package token

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The supply reveal is the only path on which this contract can
// state a disclosed amount, because it is the only one where it
// holds the plaintext. A user amount is published by the
// committee off chain and never returns here.
func TestSupplyRevealAnnouncesTheDisclosedAmount(t *testing.T) {
	f := deployToken(t)
	f.send(t, f.owner, "mint", f.owner, uint64(100))
	f.send(t, f.owner, "mint", f.other, uint64(50))

	logs := f.sendCollectingLogs(t, f.other, "revealTotalSupply")

	topic := crypto.Keccak256Hash([]byte("AmountDisclosed(bytes32,uint64)"))
	var found int
	for _, l := range logs {
		if len(l.Topics) == 0 || common.HexToHash(l.Topics[0]) != topic {
			continue
		}
		found++
		if got := common.HexToHash(l.Topics[1]); got != f.totalSupplyHandle(t) {
			t.Fatalf("announced handle %s, supply handle is %s",
				got, f.totalSupplyHandle(t))
		}
		raw, err := hex.DecodeString(common.Bytes2Hex(l.Data))
		if err != nil || len(raw) != 32 {
			t.Fatalf("amount payload is %d bytes, want 32", len(raw))
		}
		if amount := new(big.Int).SetBytes(raw).Uint64(); amount != 150 {
			t.Fatalf("announced %d, minted 150", amount)
		}
	}
	if found != 1 {
		t.Fatalf("want exactly one disclosure event, got %d", found)
	}
}

// Guard against the reading the comment warns about: a transfer
// discloses nothing, so it must not announce one.
func TestTransfersAnnounceNoDisclosure(t *testing.T) {
	f := deployToken(t)
	f.send(t, f.owner, "mint", f.owner, uint64(100))
	amount := f.balanceOf(t, f.owner)

	logs := f.sendCollectingLogs(t, f.owner,
		"confidentialTransfer", f.other, amount)

	topic := crypto.Keccak256Hash([]byte("AmountDisclosed(bytes32,uint64)"))
	for _, l := range logs {
		if len(l.Topics) > 0 && common.HexToHash(l.Topics[0]) == topic {
			t.Fatal("a transfer announced a disclosure; it discloses nothing")
		}
	}
}
