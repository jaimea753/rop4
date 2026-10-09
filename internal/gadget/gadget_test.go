package gadget_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadget"
)

// makeGadget builds a Gadget by disassembling raw bytes (mirrors rop3
// tests/conftest.make_gadget): it attaches the scan frame mask (terminator plus
// any return-address restore).
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

func setupX64(t *testing.T) (arch.Arch, *disasm.Engine) {
	t.Helper()
	a := arch.NewX64()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(eng.Close)
	return a, eng
}

func setupX86(t *testing.T) (arch.Arch, *disasm.Engine) {
	t.Helper()
	a := arch.NewX86()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(eng.Close)
	return a, eng
}

func TestTextReprAndEquality(t *testing.T) {
	a, eng := setupX64(t)
	g1 := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000) // pop rax ; ret
	g2 := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x2000) // same text, other addr
	g3 := makeGadget(t, a, eng, []byte{0x5b, 0xc3}, 0x1000) // pop rbx ; ret
	if g1.TextRepr != "pop rax ; ret" {
		t.Fatalf("text_repr = %q", g1.TextRepr)
	}
	if g1.Key() != g2.Key() { // equality/hash is text-based
		t.Errorf("same text should share a key: %q vs %q", g1.Key(), g2.Key())
	}
	if g1.Key() == g3.Key() {
		t.Errorf("different text should differ: %q", g1.Key())
	}
}

func TestCalculateSideEffectsX64(t *testing.T) {
	a, eng := setupX64(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0xff, 0xc1, 0x5d, 0xc3}, 0x1000) // inc rcx ; pop rbp ; ret
	g.CalculateSideEffects()
	if !g.SideRegs["rcx"] || !g.SideRegs["rbp"] {
		t.Fatalf("side regs = %v, want rcx and rbp", g.SideRegs)
	}
}

func TestCalculateSideEffectsX86Uses32BitNames(t *testing.T) {
	a, eng := setupX86(t)
	g := makeGadget(t, a, eng, []byte{0x41, 0x5d, 0xc3}, 0x1000) // inc ecx ; pop ebp ; ret
	g.CalculateSideEffects()
	if !g.SideRegs["ecx"] || !g.SideRegs["ebp"] {
		t.Fatalf("side regs = %v, want ecx and ebp", g.SideRegs)
	}
	if g.SideRegs["rcx"] || g.SideRegs["rbp"] {
		t.Fatalf("64-bit names leaked into a 32-bit context: %v", g.SideRegs)
	}
}

func TestSubsumes(t *testing.T) {
	a, eng := setupX64(t)
	base := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000)       // pop rax ; ret
	noisy := makeGadget(t, a, eng, []byte{0x58, 0x5b, 0xc3}, 0x2000) // pop rax ; pop rbx ; ret
	base.SideRegs = map[string]bool{}
	noisy.SideRegs = map[string]bool{"rbx": true}
	// Same dst/src (both empty here) and base's side regs subset of noisy's.
	if !base.Subsumes(noisy) {
		t.Errorf("base should subsume noisy")
	}
	if noisy.Subsumes(base) {
		t.Errorf("noisy should not subsume base")
	}
}

func TestHeuristicBasicCount(t *testing.T) {
	a, eng := setupX64(t)
	g := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000) // pop rax ; ret (2 insns)
	g.SideRegs = map[string]bool{"rbx": true}
	// 1 side reg * 4 + 2 instructions * 2 = 8
	if got := gadget.HeuristicBasicCount(g); got != 8 {
		t.Errorf("heuristic = %d, want 8", got)
	}
}

func TestStringNoColorWhenNotTTY(t *testing.T) {
	// Regression (rop3 issue #14): no ANSI escapes on non-TTY output.
	t.Setenv("NO_COLOR", "1")
	a, eng := setupX64(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0xff, 0xc1, 0xc3}, 0x1000) // inc rcx ; ret
	g.CalculateSideEffects()
	text := g.String()
	if !strings.Contains(text, "modifies") {
		t.Errorf("expected 'modifies' in %q", text)
	}
	if strings.Contains(text, "\033") {
		t.Errorf("unexpected ANSI escape in %q", text)
	}
}

func TestStringIncludesSymbol(t *testing.T) {
	a, eng := setupX64(t)
	g := makeGadget(t, a, eng, []byte{0xc3}, 0x1000) // ret
	g.Symbol = "func+0x10"
	if !strings.Contains(g.String(), "<func+0x10>") {
		t.Errorf("expected symbol in %q", g.String())
	}
}

func TestToDict(t *testing.T) {
	a, eng := setupX64(t)
	g := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000) // pop rax ; ret
	g.Count = 3
	g.Symbol = "main+0x4"
	d := g.ToDict()
	if d["file"] != "test" || d["vaddr"] != "0x1000" || d["gadget"] != "pop rax ; ret" {
		t.Fatalf("dict head = %+v", d)
	}
	if !reflect.DeepEqual(d["instructions"], []string{"pop rax", "ret"}) {
		t.Errorf("instructions = %v", d["instructions"])
	}
	if d["bytes"] != "58c3" || d["count"] != 3 || d["symbol"] != "main+0x4" {
		t.Errorf("dict = %+v", d)
	}
	if mods := d["modifies"].([]string); len(mods) != 0 {
		t.Errorf("modifies = %v, want empty", mods)
	}
}

func TestResultClobbered(t *testing.T) {
	a, eng := setupX64(t)
	ok := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xd8, 0xc3}, 0x1000)                   // add rax, rbx ; ret
	bad := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xd8, 0x48, 0x89, 0xc8, 0xc3}, 0x1010) // add rax,rbx ; mov rax,rcx ; ret
	other := makeGadget(t, a, eng, []byte{0x48, 0x01, 0xd8, 0x48, 0x31, 0xc9, 0xc3}, 0x1020) // add rax,rbx ; xor rcx,rcx ; ret
	spa := makeGadget(t, a, eng, []byte{0x48, 0x83, 0xc4, 0x08, 0xc3}, 0x1030)             // add rsp, 8 ; ret

	if !bad.ResultClobbered([]int{0}, map[string]bool{"rax": true}) {
		t.Error("bad: rax overwritten before ret -> clobbered")
	}
	if ok.ResultClobbered([]int{0}, map[string]bool{"rax": true}) {
		t.Error("ok: nothing after the add -> not clobbered")
	}
	if other.ResultClobbered([]int{0}, map[string]bool{"rax": true}) {
		t.Error("other: clobbers rcx, not the dst -> not clobbered")
	}
	if bad.ResultClobbered([]int{0}, map[string]bool{}) {
		t.Error("no destinations to guard -> not clobbered")
	}
	if bad.ResultClobbered([]int{0}, map[string]bool{"rsi": true}) {
		t.Error("an unwritten address reg guards nothing -> not clobbered")
	}
	if spa.ResultClobbered([]int{0}, map[string]bool{"rsp": true}) {
		t.Error("the terminating ret's own rsp pop is control flow -> not clobbered")
	}
}

func TestDisplayReprDimsFrameInstructions(t *testing.T) {
	// With a TTY-independent color decision, display_repr dims frame insns only
	// when color is enabled. On non-TTY (NO_COLOR) it stays plain but still only
	// renders the frame mask layout; here we assert the no-frame fallback and
	// that text_repr itself is never colored.
	a, eng := setupX64(t)
	g := makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000) // pop rax ; ret
	if g.TextRepr != "pop rax ; ret" {
		t.Fatalf("text_repr = %q", g.TextRepr)
	}
	// With no frame mask, display_repr is exactly the plain text.
	g.Frame = nil
	if g.DisplayRepr() != g.TextRepr {
		t.Errorf("display_repr without frame = %q, want %q", g.DisplayRepr(), g.TextRepr)
	}
}
