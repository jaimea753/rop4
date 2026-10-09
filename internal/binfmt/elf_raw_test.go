package binfmt

import (
	"bytes"
	"encoding/binary"
	"sort"
	"testing"
)

// --- Minimal in-memory ELF builder (Go port of conftest.build_minimal_elf) ---

const (
	emX86   = 3  // EM_386
	emX8664 = 62 // EM_X86_64
	etDyn   = 3  // ET_DYN keeps the image base at 0
)

type elfSym struct {
	name  string
	value uint64
}

// buildMinimalELF produces a tiny but valid ELF: an ELF header, a .text
// PROGBITS section flagged executable at textAddr, a .shstrtab, and (with
// symbols) a .symtab/.strtab pair.
func buildMinimalELF(elfClass, machine int, text []byte, textAddr uint64, syms []elfSym) []byte {
	is64 := elfClass == 64
	le := binary.LittleEndian

	section := func(name uint32, stype, flags uint32, addr, offset, size uint64, link, entsize uint32) []byte {
		b := new(bytes.Buffer)
		if is64 {
			binary.Write(b, le, name)
			binary.Write(b, le, stype)
			binary.Write(b, le, uint64(flags))
			binary.Write(b, le, addr)
			binary.Write(b, le, offset)
			binary.Write(b, le, size)
			binary.Write(b, le, link)
			binary.Write(b, le, uint32(0))
			binary.Write(b, le, uint64(1))
			binary.Write(b, le, uint64(entsize))
		} else {
			binary.Write(b, le, name)
			binary.Write(b, le, stype)
			binary.Write(b, le, flags)
			binary.Write(b, le, uint32(addr))
			binary.Write(b, le, uint32(offset))
			binary.Write(b, le, uint32(size))
			binary.Write(b, le, link)
			binary.Write(b, le, uint32(0))
			binary.Write(b, le, uint32(1))
			binary.Write(b, le, entsize)
		}
		return b.Bytes()
	}

	sym := func(nameOff uint32, value uint64) []byte {
		const stbGlobal, sttFunc = 1, 2
		info := byte((stbGlobal << 4) | sttFunc)
		b := new(bytes.Buffer)
		if is64 {
			binary.Write(b, le, nameOff) // st_name
			b.WriteByte(info)            // st_info
			b.WriteByte(0)               // st_other
			binary.Write(b, le, uint16(1))
			binary.Write(b, le, value)
			binary.Write(b, le, uint64(0))
		} else {
			binary.Write(b, le, nameOff)
			binary.Write(b, le, uint32(value))
			binary.Write(b, le, uint32(0))
			b.WriteByte(info)
			b.WriteByte(0)
			binary.Write(b, le, uint16(1))
		}
		return b.Bytes()
	}
	symSize := len(sym(0, 0))

	// Section-header string table (.shstrtab).
	names := []byte{0}
	addName := func(s string) uint32 {
		off := uint32(len(names))
		names = append(names, []byte(s)...)
		names = append(names, 0)
		return off
	}
	nameText := addName(".text")
	nameShstr := addName(".shstrtab")
	var nameSymtab, nameStrtab uint32
	if len(syms) > 0 {
		nameSymtab = addName(".symtab")
		nameStrtab = addName(".strtab")
	}

	// Symbol string table and entries (null symbol at index 0 is mandatory).
	strtab := []byte{0}
	symEntries := sym(0, 0)
	for _, s := range syms {
		off := uint32(len(strtab))
		strtab = append(strtab, []byte(s.name)...)
		strtab = append(strtab, 0)
		symEntries = append(symEntries, sym(off, s.value)...)
	}

	ehsize, shentsize := 64, 52
	if is64 {
		shentsize = 64
	} else {
		ehsize = 52
		shentsize = 40
	}

	textOff := uint64(ehsize)
	shstrOff := textOff + uint64(len(text))
	cursor := shstrOff + uint64(len(names))
	var symtabOff, strtabOff uint64
	if len(syms) > 0 {
		symtabOff = cursor
		strtabOff = symtabOff + uint64(len(symEntries))
		cursor = strtabOff + uint64(len(strtab))
	}
	shoff := cursor

	nSections := 3
	if len(syms) > 0 {
		nSections = 5
	}

	eiClass := byte(1)
	if is64 {
		eiClass = 2
	}
	eIdent := append([]byte("\x7fELF"), eiClass, 1, 1, 0)
	eIdent = append(eIdent, make([]byte, 8)...)

	hdr := new(bytes.Buffer)
	hdr.Write(eIdent)
	binary.Write(hdr, le, uint16(etDyn))
	binary.Write(hdr, le, uint16(machine))
	binary.Write(hdr, le, uint32(1))
	if is64 {
		binary.Write(hdr, le, textAddr)   // entry
		binary.Write(hdr, le, uint64(0))  // phoff
		binary.Write(hdr, le, shoff)      // shoff
	} else {
		binary.Write(hdr, le, uint32(textAddr))
		binary.Write(hdr, le, uint32(0))
		binary.Write(hdr, le, uint32(shoff))
	}
	binary.Write(hdr, le, uint32(0)) // flags
	binary.Write(hdr, le, uint16(ehsize))
	binary.Write(hdr, le, uint16(0)) // phentsize
	binary.Write(hdr, le, uint16(0)) // phnum
	binary.Write(hdr, le, uint16(shentsize))
	binary.Write(hdr, le, uint16(nSections))
	binary.Write(hdr, le, uint16(2)) // shstrndx

	const shtProgbits, shtSymtab, shtStrtab = 1, 2, 3
	const shfAlloc, shfExec = 0x2, 0x4

	headers := new(bytes.Buffer)
	headers.Write(section(0, 0, 0, 0, 0, 0, 0, 0))
	headers.Write(section(nameText, shtProgbits, shfAlloc|shfExec, textAddr, textOff, uint64(len(text)), 0, 0))
	headers.Write(section(nameShstr, shtStrtab, 0, 0, shstrOff, uint64(len(names)), 0, 0))

	payload := new(bytes.Buffer)
	payload.Write(text)
	payload.Write(names)
	if len(syms) > 0 {
		headers.Write(section(nameSymtab, shtSymtab, 0, 0, symtabOff, uint64(len(symEntries)), 4, uint32(symSize)))
		headers.Write(section(nameStrtab, shtStrtab, 0, 0, strtabOff, uint64(len(strtab)), 0, 0))
		payload.Write(symEntries)
		payload.Write(strtab)
	}

	out := new(bytes.Buffer)
	out.Write(hdr.Bytes())
	out.Write(payload.Bytes())
	out.Write(headers.Bytes())
	return out.Bytes()
}

var elfText = []byte{0x58, 0xc3} // pop rax ; ret

func TestELFDetectsX64(t *testing.T) {
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	bin, err := newELF(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := bin.Arch().Name(); got != "x86-64" {
		t.Errorf("arch = %q, want x86-64", got)
	}
}

func TestELFDetectsX86(t *testing.T) {
	data := buildMinimalELF(32, emX86, elfText, 0x8048000, nil)
	bin, err := newELF(data, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := bin.Arch().Name(); got != "x86" {
		t.Errorf("arch = %q, want x86", got)
	}
}

func TestELFExecSectionExtraction(t *testing.T) {
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	bin, _ := newELF(data, "")
	secs := bin.ExecSections()
	if len(secs) != 1 {
		t.Fatalf("exec sections = %d, want 1", len(secs))
	}
	if secs[0].Name != ".text" {
		t.Errorf("name = %q, want .text", secs[0].Name)
	}
	if secs[0].Vaddr != 0x1000 {
		t.Errorf("vaddr = %#x, want 0x1000", secs[0].Vaddr)
	}
	if !bytes.Equal(secs[0].Opcodes, elfText) {
		t.Errorf("opcodes = % x, want % x", secs[0].Opcodes, elfText)
	}
}

func TestELFBaseRelocationPIE(t *testing.T) {
	// --base relocates an ET_DYN image (base 0) by the requested delta.
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	bin, err := newELF(data, "0x400000")
	if err != nil {
		t.Fatal(err)
	}
	if got := bin.ExecSections()[0].Vaddr; got != 0x401000 {
		t.Errorf("rebased vaddr = %#x, want 0x401000", got)
	}
}

func TestELFNoBaseKeepsAddresses(t *testing.T) {
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	bin, _ := newELF(data, "")
	if got := bin.ExecSections()[0].Vaddr; got != 0x1000 {
		t.Errorf("vaddr = %#x, want 0x1000", got)
	}
}

func TestLoadDispatchesELFByMagic(t *testing.T) {
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	bin, err := Load(data, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if bin.Format() != "ELF" {
		t.Errorf("format = %q, want ELF", bin.Format())
	}
	if bin.Arch().Name() != "x86-64" {
		t.Errorf("arch = %q", bin.Arch().Name())
	}
}

func TestLoadUnknownFormatError(t *testing.T) {
	if _, err := Load([]byte("not a real binary header"), "", "", false); err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestELFGetSymbols(t *testing.T) {
	syms := []elfSym{{"funcA", 0x1000}, {"funcB", 0x1100}}
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, syms)
	bin, _ := newELF(data, "")
	got := bin.Symbols()
	sort.Slice(got, func(i, j int) bool { return got[i].Addr < got[j].Addr })
	if len(got) != 2 || got[0].Name != "funcA" || got[0].Addr != 0x1000 ||
		got[1].Name != "funcB" || got[1].Addr != 0x1100 {
		t.Fatalf("symbols = %+v", got)
	}
}

func TestELFGetSymbolsRebased(t *testing.T) {
	syms := []elfSym{{"funcA", 0x1000}, {"funcB", 0x1100}}
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, syms)
	bin, _ := newELF(data, "0x400000")
	got := bin.Symbols()
	sort.Slice(got, func(i, j int) bool { return got[i].Addr < got[j].Addr })
	if len(got) != 2 || got[0].Addr != 0x401000 || got[1].Addr != 0x401100 {
		t.Fatalf("rebased symbols = %+v", got)
	}
}

func TestELFNoSymbolsWhenStripped(t *testing.T) {
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	bin, _ := newELF(data, "")
	if got := bin.Symbols(); len(got) != 0 {
		t.Fatalf("expected no symbols, got %+v", got)
	}
}

// --- Raw loader -----------------------------------------------------------

func TestRawDetectsArches(t *testing.T) {
	cases := []struct {
		arch string
		want string
	}{
		{"x86_64", "x86-64"},
		{"x86", "x86"},
		{"aarch64", "AArch64 (ARM64)"},
		{"amd64", "x86-64"},  // alias
		{"arm64", "AArch64 (ARM64)"},
		{"X86_64", "x86-64"}, // case-insensitive
	}
	for _, c := range cases {
		b, err := newRaw(elfText, "", c.arch)
		if err != nil {
			t.Fatalf("newRaw(%s): %v", c.arch, err)
		}
		if got := b.Arch().Name(); got != c.want {
			t.Errorf("newRaw(%s) arch = %q, want %q", c.arch, got, c.want)
		}
	}
}

func TestRawRISCVAlignment(t *testing.T) {
	uncompressed, _ := newRaw(elfText, "", "riscv64")
	if got := uncompressed.Arch().Alignment(); got != 4 {
		t.Errorf("riscv64 alignment = %d, want 4", got)
	}
	compressed, _ := newRaw(elfText, "", "riscv64c")
	if got := compressed.Arch().Alignment(); got != 2 {
		t.Errorf("riscv64c alignment = %d, want 2", got)
	}
}

func TestRawWholeFileIsOneSection(t *testing.T) {
	b, _ := newRaw(elfText, "", "x86_64")
	secs := b.ExecSections()
	if len(secs) != 1 || secs[0].Name != "raw" || secs[0].Vaddr != 0 || !bytes.Equal(secs[0].Opcodes, elfText) {
		t.Fatalf("sections = %+v", secs)
	}
}

func TestRawBaseIsAbsoluteLoadVaddr(t *testing.T) {
	b, _ := newRaw(elfText, "0x400000", "x86_64")
	if got := b.ExecSections()[0].Vaddr; got != 0x400000 {
		t.Errorf("vaddr = %#x, want 0x400000", got)
	}
}

func TestRawRequiresArch(t *testing.T) {
	if _, err := newRaw(elfText, "", ""); err == nil {
		t.Fatal("expected an error when --arch is missing")
	}
}

func TestRawRejectsUnknownArch(t *testing.T) {
	if _, err := newRaw(elfText, "", "sparc"); err == nil {
		t.Fatal("expected an error for an unknown arch")
	}
}

func TestRawHasNoSymbols(t *testing.T) {
	b, _ := newRaw(elfText, "", "x86_64")
	if got := b.Symbols(); got != nil {
		t.Errorf("raw symbols = %+v, want nil", got)
	}
}

func TestRawGetInfo(t *testing.T) {
	b, _ := newRaw(elfText, "0x400000", "x86_64")
	info := b.Info()
	if info["format"] != "Raw" {
		t.Errorf("format = %v, want Raw", info["format"])
	}
	if info["image_base"] != uint64(0x400000) {
		t.Errorf("image_base = %v, want 0x400000", info["image_base"])
	}
}

func TestLoadRawDispatch(t *testing.T) {
	b, err := Load(elfText, "", "x86_64", true)
	if err != nil {
		t.Fatal(err)
	}
	if b.Format() != "Raw" || b.Arch().Name() != "x86-64" {
		t.Errorf("format=%q arch=%q", b.Format(), b.Arch().Name())
	}
}

func TestLoadRawIgnoresELFMagic(t *testing.T) {
	// raw forces the raw loader even when the bytes start with ELF magic.
	data := buildMinimalELF(64, emX8664, elfText, 0x1000, nil)
	b, err := Load(data, "", "x86_64", true)
	if err != nil {
		t.Fatal(err)
	}
	if b.Format() != "Raw" {
		t.Fatalf("format = %q, want Raw", b.Format())
	}
	if b.ExecSections()[0].Opcodes[0] != 0x7f {
		t.Errorf("first byte = %#x, want 0x7f (ELF magic treated as code)", b.ExecSections()[0].Opcodes[0])
	}
}
