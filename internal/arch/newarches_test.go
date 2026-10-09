package arch

import (
	"testing"

	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// disFor opens a capstone engine for a and returns a search.DisasmFunc over it.
func disFor(t *testing.T, a Arch) (search.DisasmFunc, func()) {
	t.Helper()
	e, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	dis := func(raw []byte, vaddr uint64) []*disasm.Insn {
		insns, _ := e.Disasm(raw, vaddr, 0)
		return insns
	}
	return dis, e.Close
}

func decode1(t *testing.T, dis search.DisasmFunc, b []byte) *disasm.Insn {
	t.Helper()
	ins := dis(b, 0x1000)
	if len(ins) != 1 {
		t.Fatalf("want 1 insn from % x, got %d", b, len(ins))
	}
	return ins[0]
}

// validGadget mirrors GadFinder._is_valid_gadget for ROP-only (the default).
func ropOnly(a Arch) func([]*Insn) bool {
	return func(d []*Insn) bool { return a.IsValidROPGadget(d, false, false, false) }
}

func TestAArch64DecodeAndFraming(t *testing.T) {
	a := NewAArch64()
	dis, done := disFor(t, a)
	defer done()

	ret := decode1(t, dis, []byte{0xc0, 0x03, 0x5f, 0xd6})
	if a.BaseMnemonic(ret.Mnemonic) != "ret" || !a.IsReturn(ret) {
		t.Fatalf("ret not recognized: %q", ret.Mnemonic)
	}
	// ldp x29, x30, [sp], #16 restores the return address; ldr x0,[sp] does not.
	ldp := decode1(t, dis, []byte{0xfd, 0x7b, 0xc1, 0xa8})
	if !a.RestoresReturnAddress(ldp) {
		t.Errorf("ldp x29,x30,[sp] should restore return address")
	}
	ldr0 := decode1(t, dis, []byte{0xe0, 0x07, 0x41, 0xf8})
	if a.RestoresReturnAddress(ldr0) {
		t.Errorf("ldr x0,[sp] must not count as a return-address restore")
	}
	// A valid ROP gadget must end in ret.
	if !a.IsValidROPGadget([]*Insn{ldp, ret}, false, false, false) {
		t.Errorf("ldp ; ret should be a valid ROP gadget")
	}
	if a.IsValidROPGadget([]*Insn{ldp}, false, false, false) {
		t.Errorf("ldp alone is not a ROP gadget")
	}
	// br x9 is a JOP terminator, not a ROP one.
	br := decode1(t, dis, []byte{0x20, 0x01, 0x1f, 0xd6})
	if !a.IsValidJOPGadget([]*Insn{br}, false) {
		t.Errorf("br x9 should be a valid JOP gadget")
	}
	if a.IsValidROPGadget([]*Insn{br}, false, false, false) {
		t.Errorf("br x9 is not a ROP gadget")
	}
}

// TestAArch64FramedScan: the framed aligned scan emits only runs that restore
// lr/x30 before the ret. mov x0,x1 ; ret must NOT appear (no frame); the runs
// ending at ret that cover the ldp must.
func TestAArch64FramedScan(t *testing.T) {
	a := NewAArch64()
	dis, done := disFor(t, a)
	defer done()
	// mov x0,x1 ; ldr x0,[sp],#16 ; ldp x29,x30,[sp],#16 ; ret
	blob := []byte{
		0xe0, 0x03, 0x01, 0xaa,
		0xe0, 0x07, 0x41, 0xf8,
		0xfd, 0x7b, 0xc1, 0xa8,
		0xc0, 0x03, 0x5f, 0xd6,
	}
	matches := a.Scan(blob, 0, a.DefaultDepth(), dis, ropOnly(a), nil, nil, true, false, nil)
	if len(matches) != 3 {
		t.Fatalf("framed scan: want 3 gadgets, got %d", len(matches))
	}
	for _, m := range matches {
		// Every emitted run must end on ret and its frame mask must flag the ldp.
		last := m.Decodes[len(m.Decodes)-1]
		if !a.IsReturn(last) {
			t.Errorf("gadget not ending in ret: %q", last.Mnemonic)
		}
		if !m.Frame[len(m.Frame)-1] {
			t.Errorf("terminator not framed")
		}
	}
	// Unframed: bare ret and mov;ret now appear too (plain sweep).
	un := a.Scan(blob, 0, a.DefaultDepth(), dis, ropOnly(a), nil, nil, false, false, nil)
	if len(un) <= len(matches) {
		t.Errorf("unframed scan should emit more gadgets than framed (%d vs %d)", len(un), len(matches))
	}
}

func TestRISCVReturnsAndRegs(t *testing.T) {
	a := NewRISCV(true) // compressed
	dis, done := disFor(t, a)
	defer done()

	ret := decode1(t, dis, []byte{0x67, 0x80, 0x00, 0x00})
	if !a.IsReturn(ret) {
		t.Errorf("jalr x0,0(ra) should be a return (%q)", ret.Mnemonic)
	}
	cjr := decode1(t, dis, []byte{0x82, 0x80})
	if a.BaseMnemonic(cjr.Mnemonic) != "c.jr" || !a.IsReturn(cjr) {
		t.Errorf("c.jr ra should be a return (%q %q)", cjr.Mnemonic, cjr.OpStr)
	}
	// ld ra, 8(sp) restores ra; mv a0,a1 does not and writes a0.
	ldra := decode1(t, dis, []byte{0x83, 0x30, 0x81, 0x00})
	if !a.RestoresReturnAddress(ldra) {
		t.Errorf("ld ra,8(sp) should restore the return address")
	}
	mv := decode1(t, dis, []byte{0x13, 0x85, 0x05, 0x00})
	if a.RestoresReturnAddress(mv) {
		t.Errorf("mv a0,a1 must not restore the return address")
	}
	// capstone exposes no reg-access for RISC-V; written regs come from the encoding.
	if mv.RegsOK {
		t.Logf("note: RegsOK unexpectedly true for RISC-V mv")
	}
	w := a.WrittenRegisters(mv)
	if !w["a0"] || len(w) != 1 {
		t.Errorf("mv a0,a1 written = %v, want {a0}", w)
	}
	r := a.ReadRegisters(mv)
	if !r["a1"] {
		t.Errorf("mv a0,a1 read = %v, want a1 present", r)
	}
	// ld ra writes ra (not a store/branch).
	if !a.WrittenRegisters(ldra)["ra"] {
		t.Errorf("ld ra should write ra")
	}
}

// TestRISCVFramedScan: ret jumps through ra, so a framed ROP gadget must first
// reload ra from the stack.
func TestRISCVFramedScan(t *testing.T) {
	a := NewRISCV(false)
	dis, done := disFor(t, a)
	defer done()
	// mv a0,a1 ; ld ra,8(sp) ; ret ; mv a0,a1 ; ret
	blob := []byte{
		0x13, 0x85, 0x05, 0x00,
		0x83, 0x30, 0x81, 0x00,
		0x67, 0x80, 0x00, 0x00,
		0x13, 0x85, 0x05, 0x00,
		0x67, 0x80, 0x00, 0x00,
	}
	framed := a.Scan(blob, 0, a.DefaultDepth(), dis, ropOnly(a), nil, nil, true, false, nil)
	// Only the first ret is framed (ld ra precedes it): mv;ld;ret and ld;ret.
	if len(framed) != 2 {
		t.Fatalf("framed riscv scan: want 2 gadgets, got %d", len(framed))
	}
	un := a.Scan(blob, 0, a.DefaultDepth(), dis, ropOnly(a), nil, nil, false, false, nil)
	if len(un) <= len(framed) {
		t.Errorf("unframed riscv scan should emit more (%d vs %d)", len(un), len(framed))
	}
}

func TestByteTerminationsWellFormed(t *testing.T) {
	// A sanity check on the (Galileo-only) byte patterns: sizes are consistent.
	for _, a := range []Arch{NewAArch64(), NewRISCV(false), NewRISCV(true)} {
		for _, term := range a.GetROPTerminations(false, false) {
			if len(term.Pattern) != term.Size {
				t.Errorf("%s ROP term size %d != pattern len %d", a.Name(), term.Size, len(term.Pattern))
			}
		}
		for _, term := range a.GetJOPTerminations() {
			if len(term.Pattern) != term.Size {
				t.Errorf("%s JOP term size %d != pattern len %d", a.Name(), term.Size, len(term.Pattern))
			}
		}
	}
}
