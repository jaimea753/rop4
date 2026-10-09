package ropchain_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/ropchain"
)

// x64Finder builds a GadFinder whose architecture is initialized to x86-64 by
// scanning a 1-byte raw blob (rop4 sets the arch from the first binary; the
// scan result is discarded). flags carry e.g. AllowRegAliases.
func x64Finder(t *testing.T, flags int) *gadfinder.GadFinder {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.bin")
	if err := os.WriteFile(path, []byte{0xc3}, 0o644); err != nil {
		t.Fatal(err)
	}
	gf := gadfinder.New(0, flags, 1)
	if _, err := gf.Find([]string{path}, gadfinder.FindOpts{Raw: true, ArchName: "x86_64"}); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return gf
}

func x64Engine(t *testing.T) (arch.Arch, *disasm.Engine) {
	t.Helper()
	a := arch.NewX64()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	return a, eng
}

type gspec struct {
	code  []byte
	vaddr uint64
}

func mkGadgets(t *testing.T, a arch.Arch, eng *disasm.Engine, specs []gspec) []*gadget.Gadget {
	t.Helper()
	var out []*gadget.Gadget
	for _, s := range specs {
		decodes, err := eng.Disasm(s.code, s.vaddr, 0)
		if err != nil {
			t.Fatal(err)
		}
		frame := make([]bool, len(decodes))
		last := len(decodes) - 1
		for i, ins := range decodes {
			frame[i] = i == last || a.RestoresReturnAddress(ins)
		}
		out = append(out, gadget.New("test", a, s.vaddr, decodes, s.code, frame))
	}
	return out
}

func op(name string, operands ...string) gadfinder.ChainStep {
	return gadfinder.ChainStep{Op: name, Operands: operands, Data: name + "()"}
}

func free(name string) gadfinder.ChainStep {
	return gadfinder.ChainStep{Op: "free", Free: name, Data: "free(" + name + ")"}
}

// search runs the default engine, returning all solutions (limit 0).
func search(t *testing.T, gf *gadfinder.GadFinder, gadgets []*gadget.Gadget, steps []gadfinder.ChainStep, prune bool) ([][]*gadget.Gadget, error) {
	t.Helper()
	return ropchain.New(gf).Search(gadgets, steps, prune, 0, nil)
}

func reprs(chain []*gadget.Gadget) []string {
	out := make([]string, len(chain))
	for i, g := range chain {
		out[i] = g.TextRepr
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isNotFound(err error) bool {
	var e *gadfinder.RopChainNotFound
	return errors.As(err, &e)
}

func TestSearchSimpleConcreteChain(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x58, 0xc3}, 0x1000}, // pop rax ; ret
		{[]byte{0x5b, 0xc3}, 0x1010}, // pop rbx ; ret
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("lc", "rax")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 || len(res[0]) != 1 || res[0][0].TextRepr != "pop rax ; ret" {
		t.Fatalf("result = %v", res)
	}
}

func TestSearchTwoStepChain(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x58, 0xc3}, 0x1000},
		{[]byte{0x5b, 0xc3}, 0x1010},
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("lc", "rax"), op("lc", "rbx")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"pop rax ; ret", "pop rbx ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestSearchRaisesWhenNoGadget(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{{[]byte{0x90, 0xc3}, 0x1000}}) // nop ; ret
	if _, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("lc", "rax")}, true); !isNotFound(err) {
		t.Fatalf("expected RopChainNotFound, got %v", err)
	}
}

func TestSearchGenericRegisters(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x48, 0x89, 0xd8, 0xc3}, 0x1000}, // mov rax, rbx ; ret
		{[]byte{0x48, 0x89, 0xd1, 0xc3}, 0x1010}, // mov rcx, rdx ; ret
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("mov", "REG1", "REG2")}, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if len(r) != 1 {
			t.Fatalf("each result should be one gadget, got %v", reprs(r))
		}
	}
}

func TestSameGenericSlotBothOperandsRequiresEqualRegisters(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	cross := mkGadgets(t, a, eng, []gspec{{[]byte{0x48, 0x31, 0xd8, 0xc3}, 0x1000}})   // xor rax, rbx
	self := mkGadgets(t, a, eng, []gspec{{[]byte{0x48, 0x31, 0xc0, 0xc3}, 0x1010}})    // xor rax, rax
	step := []gadfinder.ChainStep{op("xor", "REG1", "REG1")}
	if _, err := search(t, gf, cross, step, true); !isNotFound(err) {
		t.Fatalf("xor rax, rbx cannot realize xor(X, X); got %v", err)
	}
	res, err := search(t, gf, append(cross, self...), step, true)
	if err != nil {
		t.Fatal(err)
	}
	if res[0][0].TextRepr != "xor rax, rax ; ret" {
		t.Fatalf("self-xor expected, got %v", reprs(res[0]))
	}
}

func TestDistinctGenericSlotsDoNotCollapse(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	chain := []gadfinder.ChainStep{
		op("lc", "REG1"), op("lc", "REG2"),
		op("mov", "rdi", "REG1"), op("mov", "rsi", "REG2"),
	}
	oneReg := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x58, 0xc3}, 0x1000},             // pop rax ; ret
		{[]byte{0x48, 0x89, 0xc7, 0xc3}, 0x1010}, // mov rdi, rax ; ret
		{[]byte{0x48, 0x89, 0xc6, 0xc3}, 0x1020}, // mov rsi, rax ; ret
	})
	if _, err := search(t, gf, oneReg, chain, true); !isNotFound(err) {
		t.Fatalf("one register cannot fill two distinct slots; got %v", err)
	}
	twoRegs := append(oneReg, mkGadgets(t, a, eng, []gspec{
		{[]byte{0x5b, 0xc3}, 0x1030},             // pop rbx ; ret
		{[]byte{0x48, 0x89, 0xde, 0xc3}, 0x1040}, // mov rsi, rbx ; ret
	})...)
	res, err := search(t, gf, twoRegs, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	slots := map[string]bool{}
	for _, g := range res[0] {
		if g.Op == "lc" {
			slots[g.SlotOp1] = true
		}
	}
	if !slots["rax"] || !slots["rbx"] || len(slots) != 2 {
		t.Fatalf("slots = %v, want {rax, rbx}", slots)
	}
}

func TestGenericSlotNeverBindsAnImmediateMatch(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	chain := []gadfinder.ChainStep{op("add", "rax", "REG1"), op("mov", "rdi", "REG1")}
	immOnly := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x48, 0x83, 0xc0, 0x05, 0xc3}, 0x1000}, // add rax, 5 ; ret
		{[]byte{0x48, 0x89, 0xc7, 0xc3}, 0x1010},       // mov rdi, rax ; ret
	})
	if _, err := search(t, gf, immOnly, chain, true); !isNotFound(err) {
		t.Fatalf("an immediate add provides no register for REG1; got %v", err)
	}
	withReg := append(immOnly, mkGadgets(t, a, eng, []gspec{
		{[]byte{0x48, 0x01, 0xd8, 0xc3}, 0x1020}, // add rax, rbx ; ret
		{[]byte{0x48, 0x89, 0xdf, 0xc3}, 0x1030}, // mov rdi, rbx ; ret
	})...)
	res, err := search(t, gf, withReg, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"add rax, rbx ; ret", "mov rdi, rbx ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestExplicitDstClearsClobberedRegister(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x58, 0x5b, 0xc3}, 0x1000},       // pop rax ; pop rbx ; ret (clobbers rbx)
		{[]byte{0x5b, 0xc3}, 0x1010},             // pop rbx ; ret
		{[]byte{0x48, 0x89, 0xda, 0xc3}, 0x1020}, // mov rdx, rbx ; ret
	})
	chain := []gadfinder.ChainStep{op("lc", "rax"), op("lc", "rbx"), op("mov", "rdx", "rbx")}
	res, err := search(t, gf, gadgets, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"pop rax ; pop rbx ; ret", "pop rbx ; ret", "mov rdx, rbx ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestStoreDstDoesNotClearClobberedAddressRegister(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x59, 0x5b, 0xc3}, 0x1000},       // pop rcx ; pop rbx ; ret (clobbers rbx)
		{[]byte{0x48, 0x89, 0x03, 0xc3}, 0x1010}, // mov [rbx], rax ; ret (reads rbx)
		{[]byte{0x48, 0x89, 0xda, 0xc3}, 0x1020}, // mov rdx, rbx ; ret
	})
	chain := []gadfinder.ChainStep{op("lc", "rcx"), op("st", "rbx", "rax"), op("mov", "rdx", "rbx")}
	if _, err := search(t, gf, gadgets, chain, true); !isNotFound(err) {
		t.Fatalf("st must not clear rbx's clobber; got %v", err)
	}
}

func TestNaryPositionalOperands(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{{[]byte{0x48, 0x89, 0xd8, 0xc3}, 0x1000}}) // mov rax, rbx
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("mov", "rax", "rbx")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res[0][0].TextRepr != "mov rax, rbx ; ret" {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestCompoundOperationExpandsToChain(t *testing.T) {
	// eqc = sub ; neg (compound).
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x48, 0x29, 0xd8, 0xc3}, 0x1000}, // sub rax, rbx ; ret
		{[]byte{0x48, 0xf7, 0xd8, 0xc3}, 0x1010}, // neg rax ; ret
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("eqc", "rax", "rbx")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"sub rax, rbx ; ret", "neg rax ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestRegAliasesUnifyAcrossChainSteps(t *testing.T) {
	a, eng := x64Engine(t)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x66, 0x58, 0xc3}, 0x1000},       // pop ax ; ret (alias of rax)
		{[]byte{0x48, 0xf7, 0xd8, 0xc3}, 0x1010}, // neg rax ; ret
	})
	chain := []gadfinder.ChainStep{op("lc", "REG1"), op("neg", "REG1")}

	// Aliases off: pop ax cannot fill a generic slot.
	gfOff := x64Finder(t, 0)
	if _, err := search(t, gfOff, gadgets, chain, true); !isNotFound(err) {
		t.Fatalf("aliases off: expected no chain, got %v", err)
	}
	// Aliases on: pop ax unifies with neg rax under REG1.
	gfOn := x64Finder(t, gadfinder.AllowRegAliases)
	res, err := search(t, gfOn, gadgets, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"pop ax ; ret", "neg rax ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

// --- free(NAME) directive --------------------------------------------------

func TestFreeDecouplesNameReuse(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x48, 0x89, 0xd8, 0xc3}, 0x1000}, // mov rax, rbx ; ret
		{[]byte{0x48, 0x31, 0xd1, 0xc3}, 0x1010}, // xor rcx, rdx ; ret
	})
	without := []gadfinder.ChainStep{op("mov", "REG1", "REG2"), op("xor", "REG1", "REG2")}
	if _, err := search(t, gf, gadgets, without, true); !isNotFound(err) {
		t.Fatalf("without free, REG1/REG2 are one identity; got %v", err)
	}
	with := []gadfinder.ChainStep{
		op("mov", "REG1", "REG2"), free("REG1"), free("REG2"), op("xor", "REG1", "REG2"),
	}
	res, err := search(t, gf, gadgets, with, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"mov rax, rbx ; ret", "xor rcx, rdx ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestFreeSameStepBothGenericPairingEnforced(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x48, 0x89, 0xd8, 0xc3}, 0x1000}, // mov rax, rbx ; ret
		{[]byte{0x48, 0x89, 0xd1, 0xc3}, 0x1010}, // mov rcx, rdx ; ret
	})
	chain := []gadfinder.ChainStep{
		op("mov", "REG1", "REG2"), free("REG1"), free("REG2"), op("mov", "REG1", "REG2"),
	}
	res, err := search(t, gf, gadgets, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]bool{"mov rax, rbx ; ret": true, "mov rcx, rdx ; ret": true}
	for _, r := range res {
		if len(r) != 2 {
			t.Fatalf("each result should be 2 gadgets, got %v", reprs(r))
		}
		for _, g := range r {
			if !valid[g.TextRepr] {
				t.Fatalf("invalid pair: %q", g.TextRepr)
			}
		}
	}
	if len(res) != 4 {
		t.Fatalf("expected 4 results (2 choices per block), got %d", len(res))
	}
}

func TestFreeInvalidTargetWarnsAndContinues(t *testing.T) {
	// A bad free target is ignored with a warning; assembly still succeeds.
	a, eng := x64Engine(t)
	for _, badFree := range []string{"rax", "REG9"} {
		gf := x64Finder(t, 0)
		gadgets := mkGadgets(t, a, eng, []gspec{{[]byte{0x58, 0xc3}, 0x1000}}) // pop rax ; ret
		chain := []gadfinder.ChainStep{free(badFree), op("lc", "rax")}
		res, err := search(t, gf, gadgets, chain, true)
		if err != nil {
			t.Fatalf("free(%s): %v", badFree, err)
		}
		if res[0][0].TextRepr != "pop rax ; ret" {
			t.Fatalf("free(%s) result = %v", badFree, reprs(res[0]))
		}
	}
}

func TestFreeDoubleFreeWithoutUseStillAssembles(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{{[]byte{0x58, 0xc3}, 0x1000}}) // pop rax ; ret
	chain := []gadfinder.ChainStep{op("lc", "REG1"), free("REG1"), free("REG1")}
	res, err := search(t, gf, gadgets, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	if res[0][0].TextRepr != "pop rax ; ret" {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

// --- TMP_REG auto-freed scratch --------------------------------------------

var twoLsdGadgets = []gspec{
	{[]byte{0x59, 0xc3}, 0x1000},             // pop rcx ; ret
	{[]byte{0x5a, 0xc3}, 0x1010},             // pop rdx ; ret
	{[]byte{0x48, 0xf7, 0xd8, 0xc3}, 0x1020}, // neg rax ; ret
	{[]byte{0x48, 0xf7, 0xdb, 0xc3}, 0x1030}, // neg rbx ; ret
	{[]byte{0x48, 0x21, 0xc8, 0xc3}, 0x1040}, // and rax, rcx ; ret
	{[]byte{0x48, 0x21, 0xd3, 0xc3}, 0x1050}, // and rbx, rdx ; ret
}

func TestTmpRegRecognizedAsSlot(t *testing.T) {
	for _, name := range []string{"TMP_REG", "TMP_REG1"} {
		if !ropchain.IsGenericSlot(name) {
			t.Errorf("%s should be a generic slot", name)
		}
	}
	if !ropchain.IsGenericSlot("REG1") {
		t.Error("REG1 should be a generic slot")
	}
	if ropchain.IsGenericSlot("rax") {
		t.Error("rax is concrete, not a generic slot")
	}
}

func TestTmpRegAutoFreedBetweenOperations(t *testing.T) {
	// Two lsd steps whose scratch registers must differ (rcx vs rdx) assemble
	// because each operation's TMP_REG is dropped once it ends.
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, twoLsdGadgets)
	chain := []gadfinder.ChainStep{op("lsd", "rax"), op("lsd", "rbx")}
	res, err := search(t, gf, gadgets, chain, true)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, g := range res[0] {
		got[g.TextRepr] = true
	}
	if !got["and rax, rcx ; ret"] || !got["and rbx, rdx ; ret"] {
		t.Fatalf("scratch registers not decoupled: %v", reprs(res[0]))
	}
}

func TestClassifyEmitsAutofreeEventForTmpReg(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, twoLsdGadgets)
	realizations, err := gf.ClassifyRopchain(gadgets, []gadfinder.ChainStep{op("lsd", "rax")})
	if err != nil {
		t.Fatal(err)
	}
	if len(realizations) == 0 {
		t.Fatal("expected at least one realization")
	}
	found := false
	for _, fe := range realizations[0].FreeEvents {
		if fe.Boundary == 3 && fe.Name == "TMP_REG" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected autofree event (3, TMP_REG), got %+v", realizations[0].FreeEvents)
	}
}

// --- Compound operation search ---------------------------------------------

func TestSearchTriesEveryRealization(t *testing.T) {
	// Gadgets that satisfy only the non-first (rcl) realization of gcf-eqc.
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x58, 0xc3}, 0x10},             // pop rax ; ret
		{[]byte{0x48, 0x29, 0xcb, 0xc3}, 0x20}, // sub rbx, rcx ; ret
		{[]byte{0x48, 0xf7, 0xdb, 0xc3}, 0x30}, // neg rbx ; ret
		{[]byte{0x48, 0xd1, 0xd0, 0xc3}, 0x40}, // rcl rax, 1 ; ret
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("gcf-eqc", "rax", "rbx", "rcx")}, false)
	if err != nil {
		t.Fatal(err)
	}
	last := res[0][len(res[0])-1]
	if last.TextRepr != "rcl rax, 1 ; ret" {
		t.Fatalf("expected the rcl realization, got %v", reprs(res[0]))
	}
}

func TestSearchCompoundOpGcfEqc(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x5a, 0xc3}, 0x10},             // pop rdx ; ret
		{[]byte{0x5e, 0xc3}, 0x18},             // pop rsi ; ret (decoy scratch)
		{[]byte{0x48, 0x29, 0xcb, 0xc3}, 0x20}, // sub rbx, rcx ; ret
		{[]byte{0x48, 0xf7, 0xdb, 0xc3}, 0x30}, // neg rbx ; ret
		{[]byte{0x48, 0x11, 0xd0, 0xc3}, 0x40}, // adc rax, rdx ; ret
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("gcf-eqc", "rax", "rbx", "rcx")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"pop rdx ; ret", "sub rbx, rcx ; ret", "neg rbx ; ret", "adc rax, rdx ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

func TestGcfLtcRejectsFlagClobberingComparison(t *testing.T) {
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x5a, 0xc3}, 0x10},                               // pop rdx ; ret
		{[]byte{0x48, 0x29, 0xcb, 0x48, 0x85, 0xd2, 0xc3}, 0x20}, // sub rbx, rcx ; test rdx, rdx ; ret
		{[]byte{0x48, 0x11, 0xd0, 0xc3}, 0x40},                   // adc rax, rdx ; ret
	})
	if _, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("gcf-ltc")}, true); !isNotFound(err) {
		t.Fatalf("a flag-clobbering sub must block gcf-ltc; got %v", err)
	}
}

func TestSearchCompoundOpWithGenericOperands(t *testing.T) {
	// gcf-ltc() with no operands: op1/op2/op3 are free slots.
	a, eng := x64Engine(t)
	gf := x64Finder(t, 0)
	gadgets := mkGadgets(t, a, eng, []gspec{
		{[]byte{0x5a, 0xc3}, 0x10},             // pop rdx ; ret
		{[]byte{0x48, 0x29, 0xcb, 0xc3}, 0x20}, // sub rbx, rcx ; ret
		{[]byte{0x48, 0x11, 0xd0, 0xc3}, 0x40}, // adc rax, rdx ; ret
	})
	res, err := search(t, gf, gadgets, []gadfinder.ChainStep{op("gcf-ltc")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eq(reprs(res[0]), []string{"pop rdx ; ret", "sub rbx, rcx ; ret", "adc rax, rdx ; ret"}) {
		t.Fatalf("result = %v", reprs(res[0]))
	}
}

// --- ParseFile (ROP-chain file parsing) ------------------------------------

func parseFile(t *testing.T, content string) []gadfinder.ChainStep {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	steps, err := ropchain.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return steps
}

func TestParseNegativeConstantSource(t *testing.T) {
	steps := parseFile(t, "sub(rax, -1)\n")
	if len(steps) != 1 || steps[0].Op != "sub" || !eq(steps[0].Operands, []string{"rax", "-1"}) {
		t.Fatalf("parsed = %+v", steps)
	}
}

func TestParseHyphenatedOperationName(t *testing.T) {
	steps := parseFile(t, "jmp-rel(rax)\n")
	if len(steps) != 1 || steps[0].Op != "jmp-rel" || !eq(steps[0].Operands, []string{"rax"}) {
		t.Fatalf("parsed = %+v", steps)
	}
}

func TestParseThreeOperands(t *testing.T) {
	steps := parseFile(t, "add(rax, rbx, rcx)\n")
	if len(steps) != 1 || !eq(steps[0].Operands, []string{"rax", "rbx", "rcx"}) {
		t.Fatalf("parsed = %+v", steps)
	}
}

func TestParseFreeLine(t *testing.T) {
	steps := parseFile(t, "free(REG1)  ; release REG1\n")
	if len(steps) != 1 || steps[0].Op != "free" || steps[0].Free != "REG1" || len(steps[0].Operands) != 0 {
		t.Fatalf("parsed = %+v", steps)
	}
}

func TestParseFreeLineMalformedRaises(t *testing.T) {
	for _, line := range []string{"free()\n", "free(REG1, REG2)\n"} {
		path := filepath.Join(t.TempDir(), "c.txt")
		if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ropchain.ParseFile(path); err == nil {
			t.Fatalf("expected an error for %q", line)
		}
	}
}

func TestParseRawStepAccepted(t *testing.T) {
	// raw(...) ROP-chain steps are implemented: ParseFile must parse a raw line
	// into a step carrying an inline OperationDef (no catalog lookup).
	path := filepath.Join(t.TempDir(), "c.txt")
	if err := os.WriteFile(path, []byte("raw([pop, ret], [rdi], [rdi], [])\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	steps, err := ropchain.ParseFile(path)
	if err != nil {
		t.Fatalf("unexpected error parsing raw step: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("want 1 step, got %d", len(steps))
	}
	if steps[0].Defn == nil {
		t.Fatal("raw step must carry an inline OperationDef (Defn)")
	}
}
