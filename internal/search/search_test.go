package search

import (
	"sort"
	"testing"

	"github.com/reverseame/rop4/internal/disasm"
)

// x86dis opens a 64-bit x86 capstone engine and returns a DisasmFunc over it.
func x86dis(t *testing.T) (DisasmFunc, func()) {
	t.Helper()
	e, err := disasm.Open(disasm.ArchX86, disasm.Mode64)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return func(raw []byte, vaddr uint64) []*disasm.Insn {
		insns, _ := e.Disasm(raw, vaddr, 0)
		return insns
	}, e.Close
}

// isValidROP is a minimal stand-in for arch.IsValidROPGadget (avoiding an
// import cycle): a gadget ends in `ret` and no intermediate instruction is a
// terminator or unconditional branch.
func isValidROP(decodes []*disasm.Insn) bool {
	if len(decodes) == 0 {
		return false
	}
	if decodes[len(decodes)-1].Mnemonic != "ret" {
		return false
	}
	for _, ins := range decodes[:len(decodes)-1] {
		switch ins.Mnemonic {
		case "ret", "retf", "jmp", "call":
			return false
		}
	}
	return true
}

func retTerms() []Termination {
	return []Termination{{Pattern: []ByteClass{Fixed(0xc3)}, Size: 1}}
}

func textOf(d []*disasm.Insn) string {
	var parts []string
	for _, ins := range d {
		s := ins.Mnemonic
		if ins.OpStr != "" {
			s += " " + ins.OpStr
		}
		parts = append(parts, s)
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " ; "
		}
		out += p
	}
	return out
}

// byVaddr maps each gadget address to the set of gadget texts found there.
func byVaddr(ms []Match) map[uint64]map[string]bool {
	out := map[uint64]map[string]bool{}
	for _, m := range ms {
		if out[m.Vaddr] == nil {
			out[m.Vaddr] = map[string]bool{}
		}
		out[m.Vaddr][textOf(m.Decodes)] = true
	}
	return out
}

func galileo(t *testing.T, code []byte, base uint64, depth, align int) map[uint64]map[string]bool {
	dis, done := x86dis(t)
	defer done()
	ms := Galileo(code, base, retTerms(), depth, align, dis, Predicates{IsValidGadget: isValidROP})
	return byVaddr(ms)
}

func TestGalileoWalksBackwardFromEveryRet(t *testing.T) {
	res := galileo(t, []byte{0x58, 0xc3, 0x5b, 0xc3}, 0x1000, 5, 1) // pop rax;ret / pop rbx;ret
	if !res[0x1000]["pop rax ; ret"] {
		t.Error("missing pop rax ; ret at 0x1000")
	}
	if !res[0x1001]["ret"] {
		t.Error("missing ret at 0x1001")
	}
	if !res[0x1002]["pop rbx ; ret"] {
		t.Error("missing pop rbx ; ret at 0x1002")
	}
	if !res[0x1003]["ret"] {
		t.Error("missing ret at 0x1003")
	}
}

func TestGalileoRespectsDepthBound(t *testing.T) {
	res := galileo(t, []byte{0x58, 0xc3}, 0x1000, 1, 1)
	if len(res) != 1 || !res[0x1001]["ret"] {
		t.Fatalf("depth 1 should yield only {0x1001: ret}, got %v", res)
	}
}

func TestGalileoRejectsIntermediateRet(t *testing.T) {
	res := galileo(t, []byte{0x58, 0xc3, 0x5b, 0xc3}, 0x1000, 5, 1)
	if res[0x1000]["pop rax ; ret ; pop rbx ; ret"] {
		t.Error("a gadget must not span an intermediate ret")
	}
}

func TestGalileoAlignmentFiltersOddStarts(t *testing.T) {
	code := []byte{0xc3, 0x90, 0xc3, 0x90} // ret ; nop ; ret ; nop
	odd := false
	for v := range galileo(t, code, 0x1000, 5, 1) {
		if v%2 == 1 {
			odd = true
		}
	}
	if !odd {
		t.Error("alignment 1 should allow odd starts")
	}
	for v := range galileo(t, code, 0x1000, 5, 2) {
		if v%2 != 0 {
			t.Errorf("alignment 2 kept an odd start %#x", v)
		}
	}
}

func TestGalileoAcceptMatchPartitionsTerminations(t *testing.T) {
	dis, done := x86dis(t)
	defer done()
	ms := Galileo([]byte{0x58, 0xc3, 0x5b, 0xc3}, 0x1000, retTerms(), 5, 1, dis,
		Predicates{IsValidGadget: isValidROP, AcceptMatch: func(ref int) bool { return ref == 2 }})
	kept := map[uint64]bool{}
	for _, m := range ms {
		kept[m.Vaddr] = true
	}
	if len(kept) != 2 || !kept[0x1000] || !kept[0x1001] {
		t.Fatalf("accept_match should keep only the first ret's gadgets, got %v", kept)
	}
}

func TestGalileoFrameMarksOnlyTheTerminator(t *testing.T) {
	dis, done := x86dis(t)
	defer done()
	ms := Galileo([]byte{0x58, 0xc3}, 0x1000, retTerms(), 5, 1, dis, Predicates{IsValidGadget: isValidROP})
	frames := map[string][]bool{}
	for _, m := range ms {
		frames[textOf(m.Decodes)] = m.Frame
	}
	if got := frames["pop rax ; ret"]; len(got) != 2 || got[0] || !got[1] {
		t.Errorf("pop rax ; ret frame = %v, want [false true]", got)
	}
	if got := frames["ret"]; len(got) != 1 || !got[0] {
		t.Errorf("ret frame = %v, want [true]", got)
	}
}

// --- Aligned (intended-instruction) sweep ---------------------------------

// UNINTENDED: mov eax, 0xc3 ; ret -- the immediate carries a 0xc3 (ret) byte.
var unintended = []byte{0xb8, 0xc3, 0x00, 0x00, 0x00, 0xc3}

func aligned(t *testing.T, code []byte, base uint64, depth int) map[uint64]map[string]bool {
	dis, done := x86dis(t)
	defer done()
	ms := AlignedScan(code, base, depth, 1, dis, isValidROP, nil, nil, nil)
	return byVaddr(ms)
}

func TestAlignedExtractsOnlyIntendedInstructions(t *testing.T) {
	res := aligned(t, unintended, 0x1000, 8)
	if len(res[0x1000]) != 1 || !res[0x1000]["mov eax, 0xc3 ; ret"] {
		t.Errorf("0x1000 = %v, want {mov eax, 0xc3 ; ret}", res[0x1000])
	}
	if !res[0x1005]["ret"] {
		t.Errorf("0x1005 should have the ret; got %v", res[0x1005])
	}
	if len(res) != 2 {
		t.Errorf("aligned should find nothing inside the mov immediate; got %v", res)
	}
}

func TestAlignedRespectsByteDepth(t *testing.T) {
	res := aligned(t, unintended, 0x1000, 5)
	if len(res) != 1 || !res[0x1005]["ret"] {
		t.Fatalf("depth 5 should yield only {0x1005: ret}, got %v", res)
	}
}

func TestAlignedResyncsPastUndecodableTail(t *testing.T) {
	// ret then a lone 0xb8 (truncated mov) which cannot decode.
	res := aligned(t, []byte{0xc3, 0xb8}, 0x1000, 4)
	if len(res) != 1 || !res[0x1000]["ret"] {
		t.Fatalf("expected only the ret; got %v", res)
	}
}

func TestLinearInstructionsIsProgramOrder(t *testing.T) {
	dis, done := x86dis(t)
	defer done()
	insns := LinearInstructionStream(unintended, 0x1000, 1, dis)
	var mnems []string
	var addrs []uint64
	for _, i := range insns {
		mnems = append(mnems, i.Mnemonic)
		addrs = append(addrs, i.Address)
	}
	if len(mnems) != 2 || mnems[0] != "mov" || mnems[1] != "ret" {
		t.Fatalf("mnemonics = %v, want [mov ret]", mnems)
	}
	if addrs[0] != 0x1000 || addrs[1] != 0x1005 {
		t.Fatalf("addresses = %v, want [0x1000 0x1005]", addrs)
	}
}

func TestLinearInstructionsUnaffectedByChunking(t *testing.T) {
	// Chunking bounds capstone's native allocation; the stream is identical.
	// (scanChunkSize is fixed; we assert the whole-buffer invariants here.)
	dis, done := x86dis(t)
	defer done()
	insns := LinearInstructionStream(unintended, 0x1000, 1, dis)
	if len(insns) != 2 {
		t.Fatalf("stream len = %d, want 2", len(insns))
	}
}

func TestAlignedFramingRequiresReturnAddressRestore(t *testing.T) {
	// The framed aligned sweep only emits a return terminator once the backward
	// walk has covered a return-address restore. With no restore predicate ever
	// firing (as if on an arch with no ra load in this blob), a return gadget is
	// dropped; unframed (isReturn nil) it is kept -- demonstrating the gate.
	dis, done := x86dis(t)
	defer done()
	code := []byte{0x58, 0xc3} // pop rax ; ret

	framed := AlignedScan(code, 0x1000, 8, 1, dis, isValidROP,
		func(*disasm.Insn) bool { return false },            // no ra restore
		func(i *disasm.Insn) bool { return i.Mnemonic == "ret" }, nil)
	if len(framed) != 0 {
		t.Fatalf("a return gadget with no ra-restore prologue must be dropped; got %d", len(framed))
	}

	unframed := AlignedScan(code, 0x1000, 8, 1, dis, isValidROP, nil, nil, nil)
	var texts []string
	for _, m := range unframed {
		texts = append(texts, textOf(m.Decodes))
	}
	sort.Strings(texts)
	if len(texts) != 2 || texts[0] != "pop rax ; ret" || texts[1] != "ret" {
		t.Fatalf("unframed aligned = %v, want [pop rax ; ret, ret]", texts)
	}
}
