package operation_test

import (
	"testing"

	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/operation"
)

// These extend operation_test.go (which supplies setup, makeGadget, match,
// texts, textList) with the remaining high-value rop3 test_operation.py cases.

func TestLdWithSrcMatchesMemoryNotRegister(t *testing.T) {
	// Regression (#30, #33): ld (mov dst, [src]) with a concrete src matches a
	// memory load, not a register move.
	a, eng, p := setup(t)
	gadgets := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x48, 0x8b, 0x03, 0xc3}, 0x1000), // mov rax, [rbx] ; ret
		makeGadget(t, a, eng, []byte{0x48, 0x89, 0xd8, 0xc3}, 0x1010), // mov rax, rbx ; ret (must NOT match)
	}
	got := textList(match(t, a, p, "ld", []any{nil, "rbx"}, gadgets, true))
	if len(got) != 1 || got[0] != "mov rax, qword ptr [rbx] ; ret" {
		t.Fatalf("ld with src = %v", got)
	}
}

func TestLdDoesNotMatchImmediateLoad(t *testing.T) {
	// Regression (#33): a generic memory address must not resolve to an immediate.
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0xc7, 0xc0, 0xfe, 0xca, 0x00, 0x00, 0xc3}, 0x1000) // mov rax, 0xcafe ; ret
	if got := match(t, a, p, "ld", nil, []*gadget.Gadget{g}, true); len(got) != 0 {
		t.Fatalf("mov rax, imm must not be an ld, got %v", textList(got))
	}
}

func TestXchgSrcCountedAsSideEffect(t *testing.T) {
	// Regression (#31): in xchg dst, src the src register is clobbered.
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0x93, 0xc3}, 0x1000) // xchg rbx, rax ; ret
	got := match(t, a, p, "mov", []any{"rbx", "rax"}, []*gadget.Gadget{g}, true)
	if len(got) != 1 {
		t.Fatalf("xchg should realize mov, got %v", textList(got))
	}
	if !got[0].SideRegs["rax"] {
		t.Fatalf("xchg src rax should be a side effect, got %v", got[0].SideRegs)
	}
}

func TestMovMatchesClcCmovae(t *testing.T) {
	// Regression (#32): mov uses the valid capstone mnemonics cmovae/cmovb.
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0xf8, 0x48, 0x0f, 0x43, 0xc3, 0xc3}, 0x1000) // clc ; cmovae rax, rbx ; ret
	got := textList(match(t, a, p, "mov", []any{"rax", "rbx"}, []*gadget.Gadget{g}, true))
	if len(got) != 1 || got[0] != "clc ; cmovae rax, rbx ; ret" {
		t.Fatalf("clc ; cmovae = %v", got)
	}
}

func TestAddReportsSetValuedDstAndSrc(t *testing.T) {
	// add op1, op2 has dst:[op1], src:[op1, op2].
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xc2, 0xc3}, 0x1000) // add rdx, rax ; ret
	got := match(t, a, p, "add", []any{"rdx", "rax"}, []*gadget.Gadget{g}, true)
	if len(got) != 1 {
		t.Fatalf("add rdx, rax should match, got %v", textList(got))
	}
	if len(got[0].Dst) != 1 || !got[0].Dst["rdx"] {
		t.Fatalf("dst = %v, want {rdx}", got[0].Dst)
	}
	if len(got[0].Src) != 2 || !got[0].Src["rax"] || !got[0].Src["rdx"] {
		t.Fatalf("src = %v, want {rax, rdx}", got[0].Src)
	}
}

func TestSameGadgetGroupRequiresAllInstructions(t *testing.T) {
	// mov's `push op2 ; pop op1` realization must match a gadget with BOTH.
	a, eng, p := setup(t)
	gadgets := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x53, 0x58, 0xc3}, 0x1000), // push rbx ; pop rax ; ret
		makeGadget(t, a, eng, []byte{0x53, 0xc3}, 0x1010),       // push rbx ; ret
	}
	got := textList(match(t, a, p, "mov", []any{"rax", "rbx"}, gadgets, true))
	if len(got) != 1 || got[0] != "push rbx ; pop rax ; ret" {
		t.Fatalf("mov push/pop group = %v", got)
	}
}

func TestRegisterSecondOperandIsDetected(t *testing.T) {
	// Regression: `add rsp, r8` (register) must not be confused with `add rsp, 8`.
	a, eng, p := setup(t)
	r8 := makeGadget(t, a, eng, []byte{0x4c, 0x01, 0xc4, 0xc3}, 0x1000)       // add rsp, r8 ; ret
	imm := makeGadget(t, a, eng, []byte{0x48, 0x83, 0xc4, 0x08, 0xc3}, 0x1010) // add rsp, 8 ; ret
	gs := []*gadget.Gadget{r8, imm}

	if got := textList(match(t, a, p, "add", []any{"rsp", "r8"}, gs, true)); len(got) != 1 || got[0] != "add rsp, r8 ; ret" {
		t.Fatalf("add rsp, r8 = %v", got)
	}
	if got := textList(match(t, a, p, "add", []any{nil, "r8"}, gs, true)); len(got) != 1 || got[0] != "add rsp, r8 ; ret" {
		t.Fatalf("add _, r8 = %v", got)
	}
	if got := textList(match(t, a, p, "add", []any{"rsp", "8"}, gs, true)); len(got) != 1 || got[0] != "add rsp, 8 ; ret" {
		t.Fatalf("add rsp, 8 = %v", got)
	}
}

func TestRegAliasSubstitutionFlag(t *testing.T) {
	a, eng, p := setup(t)
	popAx := makeGadget(t, a, eng, []byte{0x66, 0x58, 0xc3}, 0x1000) // pop ax ; ret (alias of rax)

	defn, err := p.GetOp("lc")
	if err != nil {
		t.Fatal(err)
	}
	// Default: a sub-register does not satisfy a generic register operand.
	off, err := operation.MatchGadgets(a, false, defn, []any{nil}, []*gadget.Gadget{popAx}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 0 {
		t.Fatalf("aliases off: pop ax should not match, got %d", len(off))
	}
	// With aliases enabled it matches and normalizes to the full register.
	on, err := operation.MatchGadgets(a, true, defn, []any{nil}, []*gadget.Gadget{popAx}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(on) != 1 || on[0].TextRepr != "pop ax ; ret" {
		t.Fatalf("aliases on = %v", textList(on))
	}
	if on[0].SlotOp1 != "rax" || !on[0].Dst["rax"] {
		t.Fatalf("aliased slot/dst = %q / %v, want rax", on[0].SlotOp1, on[0].Dst)
	}
}

func TestOperandParseImmSupportsHexAndNegative(t *testing.T) {
	if v, ok := operation.ParseImmForTest("0xffffffff"); !ok || v != 0xffffffff {
		t.Errorf("0xffffffff -> %d, %v", v, ok)
	}
	if v, ok := operation.ParseImmForTest("-1"); !ok || v != -1 {
		t.Errorf("-1 -> %d, %v", v, ok)
	}
	if v, ok := operation.ParseImmForTest(42); !ok || v != 42 {
		t.Errorf("42 -> %d, %v", v, ok)
	}
}

func TestSetBindingPreservesMemoryType(t *testing.T) {
	// Regression (#33): binding a register to a [dst]/[src] placeholder keeps it memory.
	op := operation.NewOperand("[op1]")
	if !op.IsMem() {
		t.Fatal("precondition: [op1] is memory")
	}
	op.SetBindingForTest("op1", "rax")
	if !op.IsMem() || op.Reg != "rax" {
		t.Fatalf("after bind: mem=%v reg=%q", op.IsMem(), op.Reg)
	}

	src := operation.NewOperand("[op2]")
	src.SetBindingForTest("op2", "rbx")
	if !src.IsMem() || src.Reg != "rbx" {
		t.Fatalf("src after bind: mem=%v reg=%q", src.IsMem(), src.Reg)
	}
}

func TestSetBindingAcceptsImmediate(t *testing.T) {
	// Regression (#33): binding an operand to an immediate yields an imm operand.
	op := operation.NewOperand("op1")
	op.SetBindingForTest("op1", "0x10")
	if !op.IsImm() || op.Imm != 0x10 {
		t.Fatalf("after bind: imm=%v val=%#x", op.IsImm(), op.Imm)
	}
}

// --- The two-phase matching model (rop3 parametrized table) ---------------

func TestOperationMatchingModel(t *testing.T) {
	a, eng, p := setup(t)
	cases := []struct {
		desc     string
		code     []byte
		op       string
		operands []any
		expected []string
	}{
		{"op is the first instruction", []byte{0x5b, 0xc3}, "lc", []any{"rbx"}, []string{"pop rbx ; ret"}},
		{"junk before op on x86 (no prologue)", []byte{0x48, 0x89, 0xc7, 0x5b, 0xc3}, "lc", []any{"rbx"}, nil},
		{"op before the prologue is first, so matched", []byte{0x48, 0x89, 0xf7, 0x58, 0xff, 0xe0}, "mov", []any{"rdi", "rsi"}, []string{"mov rdi, rsi ; pop rax ; jmp rax"}},
		{"junk before a leading stack pivot", []byte{0xc9, 0x48, 0x01, 0xc8, 0xc3}, "add", []any{"rax", "rcx"}, nil},
		{"junk before the first of a multi-insn op", []byte{0x90, 0x53, 0x58, 0xc3}, "mov", []any{"rax", "rbx"}, nil},
		{"non-consecutive body is not matched", []byte{0x53, 0x90, 0x58, 0xc3}, "mov", []any{"rax", "rbx"}, nil},
		{"consecutive body is matched", []byte{0x53, 0x58, 0xc3}, "mov", []any{"rax", "rbx"}, []string{"push rbx ; pop rax ; ret"}},
		{"op past the first instruction on x86 (no prologue frame)", []byte{0x58, 0x48, 0x89, 0xf7, 0xff, 0xe0}, "mov", []any{"rdi", "rsi"}, nil},
		{"sp-add past the first instruction on x86 does not match", []byte{0x58, 0x48, 0x83, 0xc4, 0x08, 0xff, 0xe0}, "add", []any{"rsp", "8"}, nil},
		{"leading sp-add (ret self-frames) is a real add", []byte{0x48, 0x83, 0xc4, 0x08, 0xc3}, "add", []any{"rsp", "8"}, []string{"add rsp, 8 ; ret"}},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			g := makeGadget(t, a, eng, c.code, 0x1000)
			got := textList(match(t, a, p, c.op, c.operands, []*gadget.Gadget{g}, true))
			if len(got) != len(c.expected) {
				t.Fatalf("got %v, want %v", got, c.expected)
			}
			for i := range got {
				if got[i] != c.expected[i] {
					t.Fatalf("got %v, want %v", got, c.expected)
				}
			}
		})
	}
}

// --- tuple_repr (rop3 test_output.py tuple-format cases) ------------------

func TestTupleReprTwoOperand(t *testing.T) {
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0x89, 0xc7, 0xc3}, 0x1000) // mov rdi, rax ; ret
	got := match(t, a, p, "mov", []any{"rdi", "rax"}, []*gadget.Gadget{g}, true)
	if len(got) != 1 {
		t.Fatalf("expected a match")
	}
	if tr := got[0].TupleRepr(); tr != "⟨mov, rdi, rax, {rdi}, {rax}⟩" {
		t.Fatalf("tuple_repr = %q", tr)
	}
}

func TestTupleReprExcludesStackPointer(t *testing.T) {
	a, eng, _ := setup(t)
	g := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000) // pop rax ; ret (unmatched)
	if tr := g.TupleRepr(); tr != "⟨, {rax}, {}⟩" {
		t.Fatalf("tuple_repr = %q, want ⟨, {rax}, {}⟩ (rsp excluded)", tr)
	}
}

func TestTupleReprImmediateOperand(t *testing.T) {
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xc3}, 0x1000) // mov rax, -1 ; ret
	got := match(t, a, p, "mov", []any{"rax"}, []*gadget.Gadget{g}, true)
	if len(got) != 1 {
		t.Fatalf("expected a match, got %v", textList(got))
	}
	if tr := got[0].TupleRepr(); tr != "⟨mov, rax, -1, {rax}, {}⟩" {
		t.Fatalf("tuple_repr = %q", tr)
	}
}
