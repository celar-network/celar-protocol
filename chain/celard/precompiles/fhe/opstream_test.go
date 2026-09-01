package fhe

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func h(b byte) common.Hash { return common.BytesToHash(bytes.Repeat([]byte{b}, 32)) }

// The expected bytes are derived from the frozen §3 table by hand, NOT from
// this encoder's output. That direction is the whole point: an expectation
// taken from the encoder proves only that the encoder agrees with itself,
// which is true of a wrong one too.
func TestPackedLayoutMatchesTheSpecTable(t *testing.T) {
	got, err := packStreamEvent(0x10, 6, []common.Hash{h(0x11), h(0x22)}, h(0xAA), 3000, nil)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	want := "01" + // version
		"10" + // opcode: add
		"06" + // resultType: euint64
		"02" + // operandCount
		hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32)) +
		"00000bb8" + // hcuCost 3000, big-endian
		"0000" // auxLen
	if hex.EncodeToString(got) != want {
		t.Fatalf("layout drifted from the spec table:\n got  %s\n want %s",
			hex.EncodeToString(got), want)
	}
}

// trivialEncrypt's aux is the public value and its width. Public by
// definition, so streaming it discloses nothing.
func TestTrivialEncryptAuxLayout(t *testing.T) {
	got, err := packStreamEvent(0x02, 6, nil, h(0xAA), 10000,
		append(make([]byte, 7), 0x05, 0x40)) // value 5 (8 B BE) ‖ width 64
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	tail := hex.EncodeToString(got[len(got)-11:])
	if tail != "0009"+"0000000000000005"+"40" {
		t.Fatalf("aux tail wrong: %s", tail)
	}
}

// The decoder reads the hand-derived bytes, so encoder and decoder are
// checked against the spec rather than against each other.
func TestDecoderReadsTheSpecBytes(t *testing.T) {
	// Hand-derived from the §3 table: select (0x20), ebool result (0x00),
	// three operands, hcuCost 3000, one aux byte (a cast width, reused here
	// only as a non-empty tail).
	raw, err := hex.DecodeString("01" + "20" + "00" + "03" +
		hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x02}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x03}, 32)) +
		hex.EncodeToString(bytes.Repeat([]byte{0x09}, 32)) +
		"00000bb8" + "0001" + "40")
	if err != nil {
		t.Fatalf("fixture hex: %v", err)
	}
	e, err := DecodeStreamEvent(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Opcode != 0x20 || len(e.Operands) != 3 || e.ResultHandle != h(9) ||
		e.HCUCost != 3000 || len(e.Aux) != 1 || e.Aux[0] != 0x40 {
		t.Fatalf("round trip lost fields: %+v", e)
	}
}

// §3: an unknown envelope version MUST halt consumption, not be skipped.
func TestUnknownVersionHalts(t *testing.T) {
	packed, _ := packStreamEvent(0x10, 6, nil, h(1), 1, nil)
	packed[0] = 0x02
	if _, err := DecodeStreamEvent(packed); err == nil {
		t.Fatal("an unknown envelope version was accepted")
	}
}

func TestSchemaLimitsAreEnforced(t *testing.T) {
	if _, err := packStreamEvent(0x10, 6,
		[]common.Hash{h(1), h(2), h(3), h(4)}, h(9), 1, nil); err == nil {
		t.Fatal("four operands accepted; the schema allows three")
	}
	if _, err := packStreamEvent(0x10, 6, nil, h(9), 1, make([]byte, 0x10000)); err == nil {
		t.Fatal("aux exceeding the 2-byte length field was accepted")
	}
}
