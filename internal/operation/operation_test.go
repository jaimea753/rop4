package operation_test

import (
	"sort"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/operation"
	"github.com/reverseame/rop4/internal/roplang"
)

// makeGadget builds a Gadget by disassembling raw bytes (mirrors rop3
// tests/conftest.py make_gadget), attaching the frame mask a scan would:
// the terminator plus any return-address restore.
func makeGadget(t *testing.T, a arch.Arch, eng *disasm.Engine, code []byte, vaddr uint64) *gadget.Gadget {
	t.Helper()
	decodes, err := eng.Disasm(code, vaddr, 0)
	if err != nil {
		t.Fatalf("disasm: %v", err)
	}
	frame := make([]bool, len(decodes))
	last := len(decodes) - 1
	for i, ins := range decodes {
		frame[i] = i == last || a.RestoresReturnAddress(ins)
	}
	return gadget.New("test", a, vaddr, decodes, code, frame)
}

func texts(gs []*gadget.Gadget) map[string]bool {
	out := map[string]bool{}
	for _, g := range gs {
		out[g.TextRepr] = true
	}
	return out
}

func textList(gs []*gadget.Gadget) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.TextRepr
	}
	sort.Strings(out)
	return out
}

func dstKeys(g *gadget.Gadget) []string {
	out := make([]string, 0, len(g.Dst))
	for k := range g.Dst {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// setup returns an x86-64 arch, a capstone engine and the ROPLang parser.
func setup(t *testing.T) (arch.Arch, *disasm.Engine, *roplang.Parser) {
	t.Helper()
	a := arch.NewX64()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(eng.Close)
	p, err := roplang.New(a)
	if err != nil {
		t.Fatalf("parser: %v", err)
	}
	return a, eng, p
}

func match(t *testing.T, a arch.Arch, p *roplang.Parser, name string, operands []any,
	gadgets []*gadget.Gadget, rejectClobbered bool) []*gadget.Gadget {
	t.Helper()
	defn, err := p.GetOp(name)
	if err != nil {
		t.Fatalf("GetOp(%s): %v", name, err)
	}
	gs, err := operation.MatchGadgets(a, false, defn, operands, gadgets, rejectClobbered)
	if err != nil {
		t.Fatalf("MatchGadgets(%s): %v", name, err)
	}
	return gs
}

func TestLCMatchesPopReg(t *testing.T) {
	a, eng, p := setup(t)
	gadgets := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000), // pop rax ; ret
		makeGadget(t, a, eng, []byte{0x5b, 0xc3}, 0x1010), // pop rbx ; ret
		makeGadget(t, a, eng, []byte{0x90, 0xc3}, 0x1020), // nop ; ret
	}
	tx := texts(match(t, a, p, "lc", nil, gadgets, true))
	if !tx["pop rax ; ret"] || !tx["pop rbx ; ret"] {
		t.Fatalf("expected pop rax/rbx, got %v", tx)
	}
	if tx["nop ; ret"] {
		t.Fatalf("nop ; ret should not match lc")
	}
}

func TestLCWithDstFilter(t *testing.T) {
	a, eng, p := setup(t)
	gadgets := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000), // pop rax ; ret
		makeGadget(t, a, eng, []byte{0x5b, 0xc3}, 0x1010), // pop rbx ; ret
	}
	got := match(t, a, p, "lc", []any{"rax"}, gadgets, true)
	if textList(got)[0] != "pop rax ; ret" || len(got) != 1 {
		t.Fatalf("expected only pop rax, got %v", textList(got))
	}
	if d := dstKeys(got[0]); len(d) != 1 || d[0] != "rax" {
		t.Fatalf("expected dst {rax}, got %v", d)
	}
}

func TestFilterGadgetsEmptyInput(t *testing.T) {
	a, _, p := setup(t)
	if got := match(t, a, p, "lc", nil, nil, true); len(got) != 0 {
		t.Fatalf("expected no matches, got %v", textList(got))
	}
}

func TestFilterGadgetsDoesNotMutateInput(t *testing.T) {
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000) // pop rax ; ret
	if g.Op != "" || g.Dst != nil {
		t.Fatalf("precondition: unannotated gadget")
	}
	got := match(t, a, p, "lc", []any{"rax"}, []*gadget.Gadget{g}, true)
	if len(got) == 0 || got[0] == g {
		t.Fatalf("expected an annotated copy")
	}
	if got[0].Op != "lc" || len(got[0].Dst) != 1 || !got[0].Dst["rax"] {
		t.Fatalf("copy not annotated: op=%q dst=%v", got[0].Op, got[0].Dst)
	}
	// Original untouched.
	if g.Op != "" || g.Dst != nil || len(g.SideRegs) != 0 {
		t.Fatalf("input gadget mutated: op=%q dst=%v side=%v", g.Op, g.Dst, g.SideRegs)
	}
}

func TestClobberedDestination(t *testing.T) {
	a, eng, p := setup(t)
	good := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xd8, 0xc3}, 0x1000)                  // add rax, rbx ; ret
	bad := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xd8, 0x48, 0x89, 0xc8, 0xc3}, 0x1010) // add rax, rbx ; mov rax, rcx ; ret
	gadgets := []*gadget.Gadget{good, bad}
	if got := textList(match(t, a, p, "add", []any{"rax", "rbx"}, gadgets, true)); len(got) != 1 || got[0] != "add rax, rbx ; ret" {
		t.Fatalf("default reject: expected [add rax, rbx ; ret], got %v", got)
	}
	kept := texts(match(t, a, p, "add", []any{"rax", "rbx"}, gadgets, false))
	if !kept["add rax, rbx ; ret"] || !kept["add rax, rbx ; mov rax, rcx ; ret"] {
		t.Fatalf("keep: expected both, got %v", kept)
	}

	// Clobbering a register other than the destination is fine.
	other := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xd8, 0x48, 0x31, 0xc9, 0xc3}, 0x1020) // add rax, rbx ; xor rcx, rcx ; ret
	if got := textList(match(t, a, p, "add", []any{"rax", "rbx"}, []*gadget.Gadget{other}, true)); len(got) != 1 {
		t.Fatalf("non-dst clobber should be kept, got %v", got)
	}

	// sp is never a guarded destination; the terminator's rsp write is control flow.
	spa := makeGadget(t, a, eng, []byte{0x48, 0x83, 0xc4, 0x08, 0xc3}, 0x1030) // add rsp, 8 ; ret
	if got := textList(match(t, a, p, "add", []any{"rsp", "8"}, []*gadget.Gadget{spa}, true)); len(got) != 1 {
		t.Fatalf("add rsp, 8 should match, got %v", got)
	}

	// mov rsp pivot: intermediate rsp write is not a clobber.
	pivot := makeGadget(t, a, eng, []byte{0x48, 0x89, 0xc4, 0x5d, 0xc3}, 0x1040) // mov rsp, rax ; pop rbp ; ret
	if got := textList(match(t, a, p, "mov", []any{"rsp", "rax"}, []*gadget.Gadget{pivot}, true)); len(got) != 1 {
		t.Fatalf("mov rsp, rax pivot should match, got %v", got)
	}
}

func TestMultiInsnOpDoesNotSwallowFramingPrologue(t *testing.T) {
	a, eng, p := setup(t)
	// push rax ; pop rbx ; jmp rbx -- ropblock frame: pop rbx is the prologue.
	decodes, err := eng.Disasm([]byte{0x50, 0x5b, 0xff, 0xe3}, 0x1000, 0)
	if err != nil || len(decodes) != 3 {
		t.Fatalf("disasm: %v (%d insns)", err, len(decodes))
	}
	g := gadget.New("t", a, 0x1000, decodes, []byte{0x50, 0x5b, 0xff, 0xe3},
		[]bool{false, true, true})
	if got := match(t, a, p, "mov", []any{"rbx", "rax"}, []*gadget.Gadget{g}, true); len(got) != 0 {
		t.Fatalf("mov must not swallow the prologue, got %v", textList(got))
	}
}

func TestAbstractDstOperandDoesNotBindImmediate(t *testing.T) {
	a, eng, _ := setup(t)
	decodes, err := eng.Disasm([]byte{0x48, 0x83, 0xc0, 0x05}, 0, 0) // add rax, 5
	if err != nil || len(decodes) != 1 {
		t.Fatalf("disasm: %v", err)
	}
	decode := decodes[0]
	immOperand := decode.Operands[1] // the immediate 5

	dst := operation.NewOperand("op1")
	dst.IsDstRole = true
	if _, _, _, ok := operation.OperandEqualForTest(a, false, dst, decode, immOperand); ok {
		t.Fatalf("a dst-role abstract operand must not bind an immediate")
	}

	// A source placeholder still substitutes.
	src := operation.NewOperand("op1")
	if _, _, _, ok := operation.OperandEqualForTest(a, false, src, decode, immOperand); !ok {
		t.Fatalf("a source abstract operand should bind the immediate")
	}
}

func TestUnavailableOperation(t *testing.T) {
	a := arch.NewX64()
	defn := operation.NewOperationDef("x", 1, []string{"op1"}, nil)
	defn.MarkUnavailable("no such thing here")
	g := &gadget.Gadget{}
	if _, err := operation.MatchGadgets(a, false, defn, nil, []*gadget.Gadget{g}, true); err == nil {
		t.Fatalf("expected OperationNotAvailable error")
	} else if _, ok := err.(*operation.OperationNotAvailableError); !ok {
		t.Fatalf("expected *OperationNotAvailableError, got %T", err)
	}
}
