package fhe

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Envelope construction mirror for tests: the layout is fixed-width and the
// helper builds it the same way a client would.
func buildEnvelope(
	version byte, chainID uint64, target, submitter common.Address,
	txScope [32]byte, expiry uint64, body []byte,
) []byte {
	out := make([]byte, 0, inputProofEnvelopeLen+len(body))
	out = append(out, version)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], chainID)
	out = append(out, u64[:]...)
	out = append(out, target.Bytes()...)
	out = append(out, submitter.Bytes()...)
	out = append(out, txScope[:]...)
	binary.BigEndian.PutUint64(u64[:], expiry)
	out = append(out, u64[:]...)
	return append(out, body...)
}

var (
	tokenT     = common.HexToAddress("0xA000000000000000000000000000000000000001")
	submitterS = common.HexToAddress("0xB000000000000000000000000000000000000002")
	scope32    = [32]byte{7: 0xAA, 31: 0x01}
)

func TestEnvelopeRoundTrips(t *testing.T) {
	body := []byte("proof body bytes")
	bz := buildEnvelope(inputProofEnvelopeVersion, 23529, tokenT, submitterS,
		scope32, 4242, body)

	pub, gotBody, err := parseInputProofEnvelope(bz)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pub.ChainID != 23529 || pub.TargetContract != tokenT ||
		pub.Submitter != submitterS || pub.TxScope != scope32 ||
		pub.ExpiryHeight != 4242 {
		t.Fatalf("public inputs did not round-trip: %+v", pub)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("proof body did not round-trip")
	}
}

func TestEnvelopeMalformedIsRefusedNotGuessed(t *testing.T) {
	// Too short for the envelope at all.
	if _, _, err := parseInputProofEnvelope([]byte("short")); err == nil {
		t.Fatal("short envelope accepted")
	}
	// Right length, wrong version byte.
	bz := buildEnvelope(0x02, 23529, tokenT, submitterS, scope32, 1, nil)
	if _, _, err := parseInputProofEnvelope(bz); err == nil ||
		!strings.Contains(err.Error(), "version") {
		t.Fatal("unknown envelope version accepted")
	}
}

func pubFor(chainID, expiry uint64) InputProofPublicInputs {
	return InputProofPublicInputs{
		ChainID:        chainID,
		TargetContract: tokenT,
		Submitter:      submitterS,
		TxScope:        scope32,
		ExpiryHeight:   expiry,
	}
}

func TestAdmissionBindingChecksEveryContextFact(t *testing.T) {
	chain := big.NewInt(23529)
	const height = 1000

	// Happy path: everything agrees, expiry inside the window.
	if err := checkAdmissionBinding(
		pubFor(23529, height+100), chain, submitterS, tokenT, height,
	); err != nil {
		t.Fatalf("consistent binding refused: %v", err)
	}

	// Wrong chain.
	if err := checkAdmissionBinding(
		pubFor(1, height+100), chain, submitterS, tokenT, height,
	); err == nil || !strings.Contains(err.Error(), "chain id") {
		t.Fatal("wrong chain id accepted")
	}

	// Submitter is not the origin — a copied envelope presented by another
	// party. This is the front-running shape at the context layer.
	if err := checkAdmissionBinding(
		pubFor(23529, height+100), chain, attackerE, tokenT, height,
	); err == nil || !strings.Contains(err.Error(), "submitter") {
		t.Fatal("foreign submitter accepted")
	}

	// Target is not the admitting caller.
	if err := checkAdmissionBinding(
		pubFor(23529, height+100), chain, submitterS, attackerE, height,
	); err == nil || !strings.Contains(err.Error(), "target") {
		t.Fatal("wrong target contract accepted")
	}
}

func TestExpiryWindowBothBounds(t *testing.T) {
	chain := big.NewInt(23529)
	const height = 10_000

	// Expired: current height past the expiry.
	if err := checkAdmissionBinding(
		pubFor(23529, height-1), chain, submitterS, tokenT, height,
	); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatal("expired proof accepted")
	}

	// Boundary is inclusive: valid AT the expiry height.
	if err := checkAdmissionBinding(
		pubFor(23529, height), chain, submitterS, tokenT, height,
	); err != nil {
		t.Fatalf("proof at its expiry height refused: %v", err)
	}

	// Cap: an expiry beyond the window is refused, or the term is void.
	if err := checkAdmissionBinding(
		pubFor(23529, height+MaxExpiryWindowBlocks+1), chain, submitterS, tokenT, height,
	); err == nil || !strings.Contains(err.Error(), "too far ahead") {
		t.Fatal("astronomical expiry accepted — the freshness term is void")
	}

	// Exactly at the cap: fine.
	if err := checkAdmissionBinding(
		pubFor(23529, height+MaxExpiryWindowBlocks), chain, submitterS, tokenT, height,
	); err != nil {
		t.Fatalf("expiry exactly at the window cap refused: %v", err)
	}
}

func TestStubVerifierRefusesAnEmptyBody(t *testing.T) {
	v := stubInputProofVerifier{}
	if err := v.VerifyInputProof(pubFor(23529, 1), nil); err == nil {
		t.Fatal("empty proof body accepted")
	}
	if err := v.VerifyInputProof(pubFor(23529, 1), []byte("x")); err != nil {
		t.Fatalf("non-empty body refused by the stub: %v", err)
	}
}
