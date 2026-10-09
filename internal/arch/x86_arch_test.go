package arch

import (
	"testing"

	"github.com/reverseame/rop4/internal/disasm"
)

// termHasByte reports whether some termination's first pattern byte matches b.
func termHasByte(terms []termLike, b byte) bool {
	for _, t := range terms {
		if len(t.pat) > 0 && t.pat[0](b) {
			return true
		}
	}
	return false
}

type termLike struct {
	size int
	pat  []func(byte) bool
}

func ropTerms(a Arch, includeRetf, includeRetImm bool) []termLike {
	var out []termLike
	for _, t := range a.GetROPTerminations(includeRetf, includeRetImm) {
		tl := termLike{size: t.Size}
		for _, c := range t.Pattern {
			c := c
			tl.pat = append(tl.pat, c.Match)
		}
		out = append(out, tl)
	}
	return out
}

func TestArchModesAndPointers(t *testing.T) {
	if got := NewX86().CSMode(); got != disasm.Mode32 {
		t.Errorf("x86 mode = %v", got)
	}
	if got := NewX64().CSMode(); got != disasm.Mode64 {
		t.Errorf("x64 mode = %v", got)
	}
	if NewX86().SP() != "esp" || NewX86().BP() != "ebp" {
		t.Errorf("x86 pointers = %s/%s", NewX86().SP(), NewX86().BP())
	}
	if NewX64().SP() != "rsp" || NewX64().BP() != "rbp" {
		t.Errorf("x64 pointers = %s/%s", NewX64().SP(), NewX64().BP())
	}
}

func TestNormalizeRegX86Is32Bit(t *testing.T) {
	a := NewX86()
	for _, c := range []struct{ alias, want string }{
		{"rax", "eax"}, {"eax", "eax"}, {"ax", "eax"}, {"al", "eax"},
		{"rbp", "ebp"}, {"r8", "r8d"}, {"r8d", "r8d"}, {"r14", "r14d"},
	} {
		if got := a.NormalizeReg(c.alias); got != c.want {
			t.Errorf("x86 normalize %q = %q, want %q", c.alias, got, c.want)
		}
	}
}

func TestNormalizeRegX64Is64Bit(t *testing.T) {
	a := NewX64()
	for _, c := range []struct{ alias, want string }{
		{"rax", "rax"}, {"eax", "rax"}, {"al", "rax"},
		{"rbp", "rbp"}, {"r8d", "r8"}, {"r14", "r14"},
	} {
		if got := a.NormalizeReg(c.alias); got != c.want {
			t.Errorf("x64 normalize %q = %q, want %q", c.alias, got, c.want)
		}
	}
}

func TestNormalizeRegPassthroughUnknown(t *testing.T) {
	if NewX64().NormalizeReg("REG1") != "REG1" {
		t.Error("abstract name should pass through on x64")
	}
	if NewX86().NormalizeReg("dst") != "dst" {
		t.Error("unknown name should pass through on x86")
	}
}

func TestIsValidAbstractRegWidth(t *testing.T) {
	if !NewX64().IsValidAbstractReg("rax") || NewX64().IsValidAbstractReg("eax") {
		t.Error("x64 abstract regs are the 64-bit ones")
	}
	if !NewX86().IsValidAbstractReg("eax") || NewX86().IsValidAbstractReg("rax") {
		t.Error("x86 abstract regs are the 32-bit ones")
	}
}

func TestROPTerminationsExcludeRetImmByDefault(t *testing.T) {
	a := NewX64()
	for _, tl := range ropTerms(a, false, false) {
		if tl.size != 1 {
			t.Errorf("default termination size = %d, want only plain ret (size 1)", tl.size)
		}
	}
	found3 := false
	for _, tl := range ropTerms(a, false, true) {
		if tl.size == 3 {
			found3 = true
		}
	}
	if !found3 {
		t.Error("include_ret_imm should add a size-3 ret-imm termination")
	}
}

func TestIncludeRetfAddsRetfTermination(t *testing.T) {
	a := NewX64()
	if termHasByte(ropTerms(a, false, false), 0xcb) {
		t.Error("retf byte must be absent without include_retf")
	}
	if !termHasByte(ropTerms(a, true, false), 0xcb) {
		t.Error("retf byte must be present with include_retf")
	}
}

func TestRopTerminationMnemonicsRetfGating(t *testing.T) {
	a := NewX64().(*X64)
	if !contains(a.ropTerminationsFor(false), "ret") {
		t.Error("ret should always be a ROP terminator")
	}
	if contains(a.ropTerminationsFor(false), "retf") {
		t.Error("retf should not be a terminator by default")
	}
	if !contains(a.ropTerminationsFor(true), "retf") {
		t.Error("retf should be a terminator with include_retf")
	}
}

func TestIsValidROPGadgetRetfGating(t *testing.T) {
	a := NewX64()
	dis, done := disFor(t, a)
	defer done()
	retf := dis([]byte{0x58, 0xcb}, 0) // pop rax ; retf
	if a.IsValidROPGadget(retf, false, false, false) {
		t.Error("retf is not a plain ret")
	}
	if !a.IsValidROPGadget(retf, false, false, true) {
		t.Error("retf gadget should be valid with include_retf")
	}
}

func TestIsValidROPGadgetRetImmGating(t *testing.T) {
	a := NewX64()
	dis, done := disFor(t, a)
	defer done()
	retImm := dis([]byte{0x58, 0xc2, 0x08, 0x00}, 0) // pop rax ; ret 8
	plain := dis([]byte{0x58, 0xc3}, 0)              // pop rax ; ret
	if a.IsValidROPGadget(retImm, false, false, false) {
		t.Error("ret-imm should be rejected by default")
	}
	if !a.IsValidROPGadget(retImm, false, true, false) {
		t.Error("ret-imm should be valid with allow_ret_imm")
	}
	if !a.IsValidROPGadget(plain, false, false, false) {
		t.Error("plain ret gadget should be valid")
	}
}

func TestPrefixedConditionalBranchIsUndeterministic(t *testing.T) {
	// Regression: a prefixed conditional branch (MPX `bnd jne`) must be
	// recognized via base_mnemonic.
	a := NewX64()
	dis, done := disFor(t, a)
	defer done()
	decodes := dis([]byte{0xf2, 0x0f, 0x85, 0x00, 0x00, 0x00, 0x00, 0xc3}, 0) // bnd jne ; ret
	if len(decodes) < 2 {
		t.Fatalf("decoded %d insns", len(decodes))
	}
	if decodes[0].Mnemonic != "bnd jne" {
		t.Fatalf("mnemonic = %q, want 'bnd jne'", decodes[0].Mnemonic)
	}
	if a.BaseMnemonic(decodes[0].Mnemonic) != "jne" {
		t.Fatalf("base mnemonic = %q, want jne", a.BaseMnemonic(decodes[0].Mnemonic))
	}
	if a.IsValidROPGadget(decodes, false, false, false) {
		t.Error("an intermediate conditional branch is non-deterministic -> rejected")
	}
	if !a.IsValidROPGadget(decodes, true, false, false) {
		t.Error("allow_undeterministic should accept it")
	}
}

func TestFirstInsnHasSegmentOverride(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    Arch
	}{{"x86", NewX86()}, {"x64", NewX64()}} {
		dis, done := disFor(t, tc.a)
		plain := dis([]byte{0x89, 0x01, 0xc3}, 0)       // mov [ecx/rcx], eax ; ret
		segment := dis([]byte{0x65, 0x89, 0x01, 0xc3}, 0) // mov gs:[...], eax ; ret
		if tc.a.FirstInsnHasSegmentOverride(plain) {
			t.Errorf("%s: plain store flagged as segment override", tc.name)
		}
		if !tc.a.FirstInsnHasSegmentOverride(segment) {
			t.Errorf("%s: gs-override store not detected", tc.name)
		}
		done()
	}
}

func TestRetImmAnywhereGated(t *testing.T) {
	// A leading `ret <imm>` ends the gadget early, making the trailing
	// instructions dead -> rejected regardless of allow_ret_imm.
	a := NewX64()
	dis, done := disFor(t, a)
	defer done()
	lead := dis([]byte{0xc2, 0x48, 0x89, 0xc3}, 0) // ret 0x8948 ; ret
	if a.IsValidROPGadget(lead, false, false, false) {
		t.Error("leading ret-imm gadget should be rejected")
	}
	if a.IsValidROPGadget(lead, false, true, false) {
		t.Error("leading ret-imm gadget should be rejected even with allow_ret_imm")
	}
}

func TestScanNameAndParallelismAreArchDependent(t *testing.T) {
	if NewX86().ScanName(false, true) != "galileo" || NewX64().ScanName(false, true) != "galileo" {
		t.Error("x86/x64 use the galileo scan")
	}
	if NewRISCV(true).ScanName(false, true) != "framed aligned" {
		t.Errorf("riscv framed scan name = %q", NewRISCV(true).ScanName(false, true))
	}
	if NewAArch64().ScanName(false, true) != "framed aligned" {
		t.Errorf("aarch64 framed scan name = %q", NewAArch64().ScanName(false, true))
	}
	if NewAArch64().ScanName(false, false) != "aligned" {
		t.Error("--no-frame aarch64 -> aligned")
	}
	if NewRISCV(false).ScanName(false, false) != "aligned" {
		t.Error("--no-frame riscv -> aligned")
	}
	for _, a := range []Arch{NewX64(), NewAArch64(), NewRISCV(false)} {
		if a.ScanName(true, true) != "ropblock" {
			t.Errorf("%s ropblock scan name = %q", a.Name(), a.ScanName(true, true))
		}
	}
	if !NewX64().Parallelizable() {
		t.Error("x64 galileo is parallelizable")
	}
	if NewRISCV(true).Parallelizable() || NewAArch64().Parallelizable() {
		t.Error("fixed-width aligned scans are not parallelizable")
	}
}
