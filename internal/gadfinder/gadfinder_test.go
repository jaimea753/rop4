package gadfinder_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/gadget"
)

// writeRaw writes a raw code blob to a temp file and returns its path.
func writeRaw(t *testing.T, buf []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dump.bin")
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// findRaw scans a raw x86/x64 blob at base.
func findRaw(t *testing.T, flags int, buf []byte, base, archName string, opt gadfinder.FindOpts) []*gadget.Gadget {
	t.Helper()
	path := writeRaw(t, buf)
	gf := gadfinder.New(0, flags, 1)
	opt.Raw = true
	opt.ArchName = archName
	opt.Bases = []string{base}
	gs, err := gf.Find([]string{path}, opt)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	return gs
}

func texts(gs []*gadget.Gadget) map[string]*gadget.Gadget {
	out := map[string]*gadget.Gadget{}
	for _, g := range gs {
		out[g.TextRepr] = g
	}
	return out
}

// makeGadget builds a synthetic x64 gadget (for the FindOp path).
func makeGadget(t *testing.T, a arch.Arch, eng *disasm.Engine, code []byte, vaddr uint64) *gadget.Gadget {
	t.Helper()
	decodes, err := eng.Disasm(code, vaddr, 0)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]bool, len(decodes))
	last := len(decodes) - 1
	for i, ins := range decodes {
		frame[i] = i == last || a.RestoresReturnAddress(ins)
	}
	return gadget.New("test", a, vaddr, decodes, code, frame)
}

func TestAvoidBytesDefaultsToCanary(t *testing.T) {
	gf := gadfinder.New(0, 0, 1)
	def := gf.AvoidBytesForTest(nil)
	want := map[byte]bool{}
	for _, b := range gadfinder.CanaryBytesForTest {
		want[b] = true
	}
	if !reflect.DeepEqual(def, want) {
		t.Fatalf("default avoid = %v, want %v", def, want)
	}
	got := gf.AvoidBytesForTest([]string{"0x00", "0x0a", "0x0d", "0xff"})
	if !reflect.DeepEqual(got, map[byte]bool{0x00: true, 0x0a: true, 0x0d: true, 0xff: true}) {
		t.Fatalf("explicit canary bytes = %v", got)
	}
}

func TestAvoidBytesUsesUserBadchars(t *testing.T) {
	gf := gadfinder.New(0, 0, 1)
	got := gf.AvoidBytesForTest([]string{"0x41", "0x42"})
	if !reflect.DeepEqual(got, map[byte]bool{0x41: true, 0x42: true}) {
		t.Fatalf("user badchars = %v", got)
	}
}

func TestAddrCanaryScore(t *testing.T) {
	a := arch.NewX86()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	gf := gadfinder.New(0, 0, 1)
	gf.SetArchForTest(a)
	avoid := map[byte]bool{}
	for _, b := range gadfinder.CanaryBytesForTest {
		avoid[b] = true
	}
	clean := makeGadget(t, a, eng, []byte{0xc3}, 0x12345620)
	dirty := makeGadget(t, a, eng, []byte{0xc3}, 0x1234560a) // low byte 0x0a is a canary
	if gf.AddrCanaryScoreForTest(clean, avoid) != 0 {
		t.Error("clean address should score 0")
	}
	if gf.AddrCanaryScoreForTest(dirty, avoid) != 1 {
		t.Error("address with a 0x0a byte should score 1")
	}
}

func TestDedupPrefersCanaryFreeAddress(t *testing.T) {
	// Among duplicates keep the address with fewest canary bytes (rop3 issue #5).
	buf := make([]byte, 0x40)
	buf[0x0a] = 0xc3 // ret at ...0a (canary)
	buf[0x20] = 0xc3 // ret at ...20 (clean)
	gs := findRaw(t, gadfinder.ROP|gadfinder.AvoidCanary, buf, "0x12345600", "x86", gadfinder.FindOpts{})
	var rets []*gadget.Gadget
	for _, g := range gs {
		if g.TextRepr == "ret" {
			rets = append(rets, g)
		}
	}
	if len(rets) != 1 {
		t.Fatalf("expected 1 deduped ret, got %d", len(rets))
	}
	if rets[0].Vaddr != 0x12345620 {
		t.Errorf("kept vaddr = %#x, want 0x12345620 (canary-free)", rets[0].Vaddr)
	}
	if rets[0].Count != 2 {
		t.Errorf("count = %d, want 2", rets[0].Count)
	}
}

func TestDedupKeepsFirstSeenWithoutCanaryPreference(t *testing.T) {
	buf := make([]byte, 0x40)
	buf[0x0a] = 0xc3
	buf[0x20] = 0xc3
	gs := findRaw(t, gadfinder.ROP, buf, "0x12345600", "x86", gadfinder.FindOpts{})
	var rets []*gadget.Gadget
	for _, g := range gs {
		if g.TextRepr == "ret" {
			rets = append(rets, g)
		}
	}
	if len(rets) != 1 || rets[0].Vaddr != 0x1234560a || rets[0].Count != 2 {
		t.Fatalf("expected first-seen 0x1234560a x2, got %+v", rets)
	}
}

func TestResultsSortedByAddress(t *testing.T) {
	buf := make([]byte, 0x40)
	for _, off := range []int{0x30, 0x05, 0x18} {
		buf[off] = 0xc3
	}
	gs := findRaw(t, gadfinder.ROP, buf, "0x10000", "x86", gadfinder.FindOpts{})
	var vaddrs []uint64
	for _, g := range gs {
		vaddrs = append(vaddrs, g.Vaddr)
	}
	if !sort.SliceIsSorted(vaddrs, func(i, j int) bool { return vaddrs[i] < vaddrs[j] }) {
		t.Fatalf("not sorted: %v", vaddrs)
	}
}

func TestBadcharBytesFiltersOnOpcodeBytes(t *testing.T) {
	// Reject gadgets whose opcode bytes contain a forbidden byte (rop3 issue #21).
	buf := make([]byte, 0x40)
	buf[0x10] = 0xc3             // ret
	buf[0x20] = 0x5d             // pop ebp
	buf[0x21] = 0xc3             // ret
	gs := findRaw(t, gadfinder.ROP, buf, "0x10000", "x86", gadfinder.FindOpts{BadcharBytes: []string{"0x5d"}})
	tx := texts(gs)
	if _, ok := tx["ret"]; !ok {
		t.Error("ret should remain")
	}
	if _, ok := tx["pop ebp ; ret"]; ok {
		t.Error("pop ebp ; ret contains the forbidden 0x5d byte")
	}
	for _, g := range gs {
		for _, b := range g.Bytes {
			if b == 0x5d {
				t.Fatalf("gadget %q retains a 0x5d byte", g.TextRepr)
			}
		}
	}
}

func TestRetImmGadgetsGatedByFlag(t *testing.T) {
	buf := make([]byte, 0x40)
	copy(buf[0x10:], []byte{0x58, 0xc2, 0x08, 0x00}) // pop eax ; ret 8
	def := findRaw(t, gadfinder.ROP, buf, "0x12345600", "x86", gadfinder.FindOpts{})
	for _, g := range def {
		if g.TextRepr == "pop eax ; ret 8" {
			t.Fatal("ret-imm gadget must be absent by default")
		}
	}
	withImm := texts(findRaw(t, gadfinder.ROP|gadfinder.AllowRetImm, buf, "0x12345600", "x86", gadfinder.FindOpts{}))
	if _, ok := withImm["pop eax ; ret 8"]; !ok {
		t.Fatal("ret-imm gadget should appear with AllowRetImm")
	}
}

func TestClassicalScanPopulatesFrameMask(t *testing.T) {
	// Ordinary gadgets carry a frame mask marking the terminator; a stack
	// adjustment is a side effect, not framing.
	buf := []byte{0x58, 0xc3} // pop eax ; ret
	g := texts(findRaw(t, gadfinder.ROP, buf, "0x400000", "x86", gadfinder.FindOpts{}))["pop eax ; ret"]
	if g == nil {
		t.Fatal("pop eax ; ret not found")
	}
	if !reflect.DeepEqual(g.Frame, []bool{false, true}) {
		t.Errorf("frame = %v, want [false true]", g.Frame)
	}

	buf2 := []byte{0x83, 0xc4, 0x08, 0xc3} // add esp, 8 ; ret
	g2 := texts(findRaw(t, gadfinder.ROP, buf2, "0x400000", "x86", gadfinder.FindOpts{}))["add esp, 8 ; ret"]
	if g2 == nil {
		t.Fatal("add esp, 8 ; ret not found")
	}
	if !reflect.DeepEqual(g2.Frame, []bool{false, true}) {
		t.Errorf("frame = %v, want [false true]", g2.Frame)
	}
}

func TestNearestSymbolAnnotation(t *testing.T) {
	// Gadgets get the nearest symbol at or below their address (rop3 issue #22).
	syms := []binfmt.Symbol{{Addr: 0x10000, Name: "start"}, {Addr: 0x10020, Name: "middle"}}
	if got := gadfinder.NearestSymbolForTest(syms, 0x10010); got != "start+0x10" {
		t.Errorf("nearest(0x10010) = %q, want start+0x10", got)
	}
	if got := gadfinder.NearestSymbolForTest(syms, 0x10030); got != "middle+0x10" {
		t.Errorf("nearest(0x10030) = %q, want middle+0x10", got)
	}
	// Exact address -> no +offset suffix.
	if got := gadfinder.NearestSymbolForTest(syms, 0x10000); got != "start" {
		t.Errorf("nearest(0x10000) = %q, want start", got)
	}
}

func TestFindOpResolvesSPAliasAndGenericOperands(t *testing.T) {
	// --op/--operands apply the REG_SP/REG_BP aliases and the generic-slot ->
	// "any register" mapping, like a .ropchain file.
	a := arch.NewX64()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	gf := gadfinder.New(0, 0, 1)
	gf.SetArchForTest(a)
	gadgets := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x48, 0x89, 0xe0, 0xc3}, 0x1000), // mov rax, rsp ; ret
		makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1010),            // pop rax ; ret
	}
	spMatch, err := gf.FindOp(gadgets, "mov", []string{"rax", "REG_SP"})
	if err != nil {
		t.Fatal(err)
	}
	if len(spMatch) != 1 || spMatch[0].TextRepr != "mov rax, rsp ; ret" {
		t.Fatalf("mov(rax, REG_SP) = %v", textList(spMatch))
	}
	generic, err := gf.FindOp(gadgets, "lc", []string{"reg1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(generic) != 1 || generic[0].TextRepr != "pop rax ; ret" {
		t.Fatalf("lc(reg1) = %v", textList(generic))
	}
}

func textList(gs []*gadget.Gadget) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.TextRepr
	}
	return out
}
