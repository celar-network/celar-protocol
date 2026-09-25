package relayer_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/evm/evmd/relayer"
)

// The vector lives at the repository root: neutral ground, read by both
// implementations, owned by neither.
func vector(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "testdata", "handoff", "vector.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("shared vector unreadable at %s: %v", p, err)
	}
	return b
}

func TestParsesTheSharedVector(t *testing.T) {
	got, err := relayer.ParseHandoff(vector(t))
	if err != nil {
		t.Fatalf("the vector must parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 attestation, got %d", len(got))
	}

	a := got[0]
	if a.Height != 5 || a.TxIndex != 1 || a.LogIndex != 2 {
		t.Fatalf("position lost in translation: %+v", a)
	}
	if !bytes.Equal(a.ResultHandle, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("result handle wrong: %x", a.ResultHandle)
	}
	if !bytes.Equal(a.CtDigest, bytes.Repeat([]byte{0xcd}, 32)) {
		t.Fatalf("ct digest wrong: %x", a.CtDigest)
	}
	if !bytes.Equal(a.CoprocessorId, bytes.Repeat([]byte{0x11}, 20)) {
		t.Fatalf("coprocessor id wrong: %x", a.CoprocessorId)
	}
	if !bytes.Equal(a.Signature, bytes.Repeat([]byte{0x22}, 65)) {
		t.Fatalf("signature wrong: %x", a.Signature)
	}
	if a.EnvVersion != 1 {
		t.Fatalf("env version wrong: %d", a.EnvVersion)
	}
}

// The refusals. A malformed handoff must fail here, cheaply, rather than as a
// rejected transaction whose error names the chain's reason and not the file's.

func TestRefusesAWrongWidthAndNamesWhichOne(t *testing.T) {
	// A signature one byte short. Everything else is well formed, which is the
	// case that would otherwise reach the chain and be refused there.
	doc := strings.Replace(string(vector(t)), strings.Repeat("22", 65), strings.Repeat("22", 64), 1)

	_, err := relayer.ParseHandoff([]byte(doc))
	if err == nil {
		t.Fatal("a short signature must be refused before a transaction is built")
	}
	if !strings.Contains(err.Error(), "signature") || !strings.Contains(err.Error(), "attestation 0") {
		t.Fatalf("the refusal must name the field and the index: %v", err)
	}
}

func TestRefusesAnAbsentFieldRatherThanZeroingIt(t *testing.T) {
	// An absent hex field decodes to zero bytes and would otherwise pass as an
	// empty value, producing an attestation that cannot verify and a diagnosis
	// pointing at the signature rather than at the file.
	doc := strings.Replace(string(vector(t)), `"ct_digest":"`+strings.Repeat("cd", 32)+`"`, `"ct_digest":""`, 1)

	_, err := relayer.ParseHandoff([]byte(doc))
	if err == nil {
		t.Fatal("an absent digest must be refused")
	}
	if !strings.Contains(err.Error(), "ct_digest") {
		t.Fatalf("the refusal must name the field: %v", err)
	}
}

func TestAnEmptyBatchIsNotAnError(t *testing.T) {
	got, err := relayer.ParseHandoff([]byte(`{"attestations":[]}`))
	if err != nil {
		t.Fatalf("a poll that executed nothing is legitimate: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want none, got %d", len(got))
	}
}
