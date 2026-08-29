package fhe

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// Front-running the admission path — refuted.
//
// verifyInput now derives its handle as
// keccak256(domainTag || "verifyInput" || submitter || (ciphertext, proof)),
// where the submitter is the transaction origin. registerHandle remains
// first-writer-wins, but copying someone's (ciphertext, proof) no longer
// reaches their handle: the copy derives one of the copier's own.
//
// These tests were written the other way round. They asserted the
// vulnerability — that ordering alone decided ownership, and that a
// front-runner could self-grant reveal and have the committee disclose a
// victim's plaintext. They now assert the protection, and the history is
// worth keeping in view: the attack was demonstrated before it was fixed,
// and the same file records both.
//
// They do not simulate a mempool. They isolate the claim: whether the
// preimage binds the submitter.

var (
	victimV   = common.HexToAddress("0xD000000000000000000000000000000000000004")
	attackerE = common.HexToAddress("0xE000000000000000000000000000000000000005")
)

// admissionHandle reproduces exactly what Run does for verifyInput.
func admissionHandle(
	t *testing.T, p *Precompile, ct, proof []byte,
	submitter common.Address,
) common.Hash {
	t.Helper()
	m := p.abi.Methods[VerifyInputMethod]
	argBz, err := m.Inputs.Pack(ct, proof)
	if err != nil {
		t.Fatalf("pack verifyInput args: %v", err)
	}
	// Calls the same function Run calls. This helper used to
	// re-implement the derivation, and when Run gained the submitter the
	// copy did not — so these tests passed against a formula the chain
	// had stopped using. A test that mirrors production logic stops
	// testing it the moment production changes, and reports success.
	return p.deriveAdmissionHandle(&m, argBz, submitter)
}

// The submitter is in the preimage, so identical inputs from different
// submitters no longer collide. Inverted from asserting the vulnerability
// to asserting the protection.
func TestAdmissionHandleIsBoundToSubmitter(t *testing.T) {
	p := mustPrecompile(t)
	ct := []byte("victim ciphertext bytes")
	proof := []byte("victim input proof")

	// Still deterministic for one submitter — without this, a derivation
	// that had merely become random would pass the check below.
	if admissionHandle(t, p, ct, proof, victimV) !=
		admissionHandle(t, p, ct, proof, victimV) {
		t.Fatal("derivation is not deterministic for a single submitter")
	}

	if admissionHandle(t, p, ct, proof, victimV) ==
		admissionHandle(t, p, ct, proof, attackerE) {
		t.Fatal("handles collide across submitters — " +
			"the submitter is not in the preimage")
	}
}

// The attack, refuted. Copying (ct, proof) and landing first now yields
// the attacker a handle of their own, and leaves the victim's alone.
func TestFrontRunnerCannotStealAdmittedInput(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	ct := []byte("victim ciphertext bytes")
	proof := []byte("victim input proof")
	h := admissionHandle(t, p, ct, proof, victimV)
	attackerH := admissionHandle(t, p, ct, proof, attackerE)

	// 1. the attacker copies (ct, proof) and lands first — but the handle
	//    they register derives from THEIR address, not the victim's.
	p.registerHandle(db, attackerH, attackerE, KTypeUnknown, false)
	// 2. the victim's own transaction then executes, unaffected.
	p.registerHandle(db, h, victimV, KTypeUnknown, false)

	if got := metaOwner(p.getMeta(db, h)); got != victimV {
		t.Fatalf("victim lost their own handle; owner = %s", got.Hex())
	}

	// 3. the attacker cannot grant themselves anything on the victim's
	//    handle: they are not its owner.
	am := p.abi.Methods[AllowMethod]
	allowArgs, err := am.Inputs.Pack(
		[32]byte(h), attackerE, uint8(2),
	)
	if err != nil {
		t.Fatalf("pack allow args: %v", err)
	}
	if _, err := p.runAllow(
		db, attackerE, &am, allowArgs,
	); err == nil {
		t.Fatal("attacker self-granted on a handle they do not own")
	}

	// 4. so the committee will not serve them a reveal of it. The refusal
	//    comes from the grant check rather than an ownership check — the
	//    attacker holds no reveal grant on a handle that is not theirs.
	wantErr(t, p.checkServable(
		db, attackerE, RequestRevealMethod, h.Bytes(),
	), "reveal not granted")

	// 5. and the victim retains access to their own input.
	if err := p.checkServable(
		db, victimV, RequestReencryptMethod, h.Bytes(),
	); err != nil {
		t.Fatalf("victim refused their own re-encryption: %v", err)
	}

	// The attacker keeps what they actually admitted — their own copy.
	// That is not the attack; it is a user admitting a ciphertext.
	if got := metaOwner(p.getMeta(db, attackerH)); got != attackerE {
		t.Fatalf("attacker's own handle not theirs: %s", got.Hex())
	}
}

// Control: identical state, only the ordering differs.
func TestWithoutFrontRunVictimRetainsControl(t *testing.T) {
	p, db := mustPrecompile(t), newFakeStore()
	h := admissionHandle(t, p,
		[]byte("victim ciphertext bytes"),
		[]byte("victim input proof"), victimV)

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
