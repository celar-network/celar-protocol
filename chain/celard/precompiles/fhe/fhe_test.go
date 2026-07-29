package fhe

import (
	"testing"
)

// TestHandleDeterminism: same method+args => same handle; any difference
// in method or args => different handle. This is the determinism
// property at stub level
func TestHandleDeterminism(t *testing.T) {
	p, err := NewPrecompile()
	if err != nil {
		t.Fatalf("NewPrecompile: %v", err)
	}
	add := p.abi.Methods[AddMethod]
	sub := p.abi.Methods[SubMethod]

	args := make([]byte, 64) // two zero bytes32 args
	args[31] = 0x01          //a = 0x...01
	args[63] = 0x02          //a = 0x...02

	h1, err := p.packHandle(&add, args)
	if err != nil {
		t.Fatalf("packHandle: %v", err)
	}
	h2, _ := p.packHandle(&add, args)
	if string(h1) != string(h2) {
		t.Fatalf("different args produced the same handle")
	}

	argsB := make([]byte, 64)
	argsB[31] = 0x01
	argsB[63] = 0x03 //b differs
	h3, _ := p.packHandle(&add, argsB)
	if string(h1) == string(h3) {
		t.Fatalf("different args produced the same handle")
	}

	h4, _ := p.packHandle(&sub, args)
	if string(h1) == string(h4) {
		t.Fatalf("different args produced the same handle")
	}
}

// TestPrintSelectors logs each methods 4f-byte selector for use in
// eth_call smoke tests.
func TestPrintSelectors(t *testing.T) {
	p, err := NewPrecompile()
	if err != nil {
		t.Fatalf("NewPrecompile: %v", err)
	}
	for name, m := range p.abi.Methods {
		t.Logf("%-18s 0x%x", name, m.ID)
	}
}
