package fhe

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Admission is the one op whose aux carries material rather than parameters,
// and the one whose result type is genuinely unknown at emission. Both are
// schema rules rather than choices made here, so both are asserted.
func TestAdmissionAuxIsACommitmentThenAnUnpopulatedPointer(t *testing.T) {
	p := mustPrecompile(t)
	m := p.abi.Methods[VerifyInputMethod]

	ct := []byte("submitted ciphertext bytes, exactly as presented")
	argBz, err := m.Inputs.Pack(ct, []byte("input proof"))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	aux, err := streamAux(&m, argBz)
	if err != nil {
		t.Fatalf("streamAux: %v", err)
	}
	if len(aux) != 64 {
		t.Fatalf("aux is %d bytes, schema fixes it at 64", len(aux))
	}

	// Hashed here rather than through the encoder's own path: a commitment
	// checked against the function that produced it agrees with itself.
	want := crypto.Keccak256(ct)
	if !bytes.Equal(aux[:32], want) {
		t.Fatalf("commitment is not keccak256 over the submitted bytes")
	}

	// The commitment must be over the bytes as they arrived. Hashing a
	// re-encoded or trimmed form would still be 32 bytes and still look right.
	if bytes.Equal(aux[:32], crypto.Keccak256(ct[:len(ct)-1])) {
		t.Fatal("commitment does not cover the whole submitted string")
	}

	if !bytes.Equal(aux[32:], make([]byte, 32)) {
		t.Fatal("data-availability pointer must be all-zero while unpopulated")
	}
}

// The schema reserves 0xFF for a result whose plaintext type the emitting op
// makes no claim about. Admission cannot know it: the frozen signature carries
// no width and the submitter does not have one either.
func TestAdmissionRegistersTheReservedUnknownType(t *testing.T) {
	if KTypeUnknown != 0xFF {
		t.Fatalf("reserved unknown type is %#x, schema says 0xFF", KTypeUnknown)
	}
}
