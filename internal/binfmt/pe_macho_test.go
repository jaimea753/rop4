package binfmt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// gadgetText is a short x86-64 blob (ret-terminated sequences) reused by both
// builders; its exact contents do not matter to these loader tests.
var gadgetText = []byte{
	0x48, 0x89, 0xc3, 0x5b, 0x5d, 0xc3, // mov rbx,rax; pop rbx; pop rbp; ret
	0x58, 0xc3, // pop rax; ret
	0xc3, // ret
}

// --- Minimal PE32+ (amd64) builder (Go port of the validated Python one) ----

func buildPE32Plus(t *testing.T, machine uint16, text []byte, textRVA uint32, imageBase uint64) []byte {
	t.Helper()
	const (
		fileAlign = 0x200
		sectAlign = 0x1000
		nDirs     = 16
		scnCode   = 0x20
		scnExec   = 0x20000000
		scnRead   = 0x40000000
	)
	le := binary.LittleEndian

	optHead := new(bytes.Buffer)
	binary.Write(optHead, le, uint16(0x20b)) // PE32+ magic
	optHead.Write([]byte{1, 0})              // Major/Minor linker
	binary.Write(optHead, le, uint32(len(text)))
	binary.Write(optHead, le, uint32(0)) // SizeOfInitializedData
	binary.Write(optHead, le, uint32(0)) // SizeOfUninitializedData
	binary.Write(optHead, le, textRVA)   // AddressOfEntryPoint
	binary.Write(optHead, le, textRVA)   // BaseOfCode
	binary.Write(optHead, le, imageBase)
	binary.Write(optHead, le, uint32(sectAlign))
	binary.Write(optHead, le, uint32(fileAlign))
	for _, v := range []uint16{6, 0, 0, 0, 6, 0} { // OS/Image/Subsystem versions
		binary.Write(optHead, le, v)
	}
	binary.Write(optHead, le, uint32(0)) // Win32VersionValue

	sizeOfImage := uint32(sectAlign + ((len(text)+sectAlign-1)/sectAlign)*sectAlign)

	optTail := new(bytes.Buffer)
	binary.Write(optTail, le, uint32(0)) // CheckSum
	binary.Write(optTail, le, uint16(3)) // Subsystem
	binary.Write(optTail, le, uint16(0)) // DllCharacteristics
	for _, v := range []uint64{0x100000, 0x1000, 0x100000, 0x1000} {
		binary.Write(optTail, le, v)
	}
	binary.Write(optTail, le, uint32(0))     // LoaderFlags
	binary.Write(optTail, le, uint32(nDirs)) // NumberOfRvaAndSizes
	optTail.Write(make([]byte, 8*nDirs))     // data directories (empty)

	optionalHeader := func(sizeOfHeaders uint32) []byte {
		b := new(bytes.Buffer)
		b.Write(optHead.Bytes())
		binary.Write(b, le, sizeOfImage)
		binary.Write(b, le, sizeOfHeaders)
		b.Write(optTail.Bytes())
		return b.Bytes()
	}
	optSize := len(optionalHeader(0))

	coff := new(bytes.Buffer)
	binary.Write(coff, le, machine)
	binary.Write(coff, le, uint16(1)) // NumberOfSections
	binary.Write(coff, le, uint32(0)) // TimeDateStamp
	binary.Write(coff, le, uint32(0)) // PointerToSymbolTable
	binary.Write(coff, le, uint32(0)) // NumberOfSymbols
	binary.Write(coff, le, uint16(optSize))
	binary.Write(coff, le, uint16(0x22)) // Characteristics

	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	le.PutUint32(dos[0x3c:], 0x40) // e_lfanew
	peSig := []byte("PE\x00\x00")

	sectionHdrOff := 0x40 + len(peSig) + coff.Len() + optSize
	sizeOfHeaders := uint32(((sectionHdrOff + 40 + fileAlign - 1) / fileAlign) * fileAlign)
	rawPtr := sizeOfHeaders

	section := new(bytes.Buffer)
	name := make([]byte, 8)
	copy(name, ".text")
	section.Write(name)
	binary.Write(section, le, uint32(len(text))) // VirtualSize
	binary.Write(section, le, textRVA)           // VirtualAddress
	binary.Write(section, le, uint32(len(text))) // SizeOfRawData
	binary.Write(section, le, rawPtr)            // PointerToRawData
	binary.Write(section, le, uint32(0))         // PointerToRelocations
	binary.Write(section, le, uint32(0))         // PointerToLineNumbers
	binary.Write(section, le, uint16(0))         // NumberOfRelocations
	binary.Write(section, le, uint16(0))         // NumberOfLineNumbers
	binary.Write(section, le, uint32(scnCode|scnExec|scnRead))

	blob := new(bytes.Buffer)
	blob.Write(dos)
	blob.Write(peSig)
	blob.Write(coff.Bytes())
	blob.Write(optionalHeader(sizeOfHeaders))
	blob.Write(section.Bytes())
	if blob.Len() < int(rawPtr) {
		blob.Write(make([]byte, int(rawPtr)-blob.Len()))
	}
	blob.Write(text)
	return blob.Bytes()
}

// --- Minimal thin Mach-O (x86_64) builder with an LC_SYMTAB -----------------

func buildThinMachO(t *testing.T, cputype int32, text []byte, textAddr uint64, syms []Symbol) []byte {
	t.Helper()
	const (
		mhMagic64    = 0xfeedfacf
		lcSegment64  = 0x19
		lcSymtab     = 0x2
		mhExecute    = 2
		vmRead       = 0x1
		vmExec       = 0x4
		sSomeInstr   = 0x400
		nSect, nExt  = 0xe, 0x1
		segCmdSize   = 72 + 80 // segment_command_64 + one section_64
		symtabCmdLen = 24
		nlistSize    = 16
	)
	le := binary.LittleEndian

	hasSyms := len(syms) > 0
	ncmds := uint32(1)
	sizeofcmds := uint32(segCmdSize)
	if hasSyms {
		ncmds = 2
		sizeofcmds += symtabCmdLen
	}
	textOff := 32 + sizeofcmds

	// Symbol + string tables (after __text).
	strtab := []byte{0}
	symEntries := new(bytes.Buffer)
	for _, s := range syms {
		nStrx := uint32(len(strtab))
		strtab = append(strtab, []byte(s.Name)...)
		strtab = append(strtab, 0)
		binary.Write(symEntries, le, nStrx)      // n_strx
		symEntries.WriteByte(byte(nSect | nExt)) // n_type
		symEntries.WriteByte(1)                  // n_sect
		binary.Write(symEntries, le, uint16(0))  // n_desc
		binary.Write(symEntries, le, s.Addr)     // n_value
	}
	symoff := textOff + uint32(len(text))
	stroff := symoff + uint32(symEntries.Len())

	buf := new(bytes.Buffer)
	// mach_header_64
	binary.Write(buf, le, uint32(mhMagic64))
	binary.Write(buf, le, cputype)
	binary.Write(buf, le, int32(0)) // cpusubtype
	binary.Write(buf, le, uint32(mhExecute))
	binary.Write(buf, le, ncmds)
	binary.Write(buf, le, sizeofcmds)
	binary.Write(buf, le, uint32(0))
	binary.Write(buf, le, uint32(0))

	// LC_SEGMENT_64 __TEXT
	seg := make([]byte, 16)
	copy(seg, "__TEXT")
	binary.Write(buf, le, uint32(lcSegment64))
	binary.Write(buf, le, uint32(segCmdSize))
	buf.Write(seg)
	binary.Write(buf, le, textAddr)             // vmaddr
	binary.Write(buf, le, uint64(len(text)))    // vmsize
	binary.Write(buf, le, uint64(textOff))      // fileoff
	binary.Write(buf, le, uint64(len(text)))    // filesize
	binary.Write(buf, le, int32(vmRead|vmExec)) // maxprot
	binary.Write(buf, le, int32(vmRead|vmExec)) // initprot
	binary.Write(buf, le, uint32(1))            // nsects
	binary.Write(buf, le, uint32(0))            // flags

	// section_64 __text
	sect := make([]byte, 16)
	copy(sect, "__text")
	buf.Write(sect)
	buf.Write(seg)
	binary.Write(buf, le, textAddr)           // addr
	binary.Write(buf, le, uint64(len(text)))  // size
	binary.Write(buf, le, uint32(textOff))    // offset
	binary.Write(buf, le, uint32(2))          // align
	binary.Write(buf, le, uint32(0))          // reloff
	binary.Write(buf, le, uint32(0))          // nreloc
	binary.Write(buf, le, uint32(sSomeInstr)) // flags
	binary.Write(buf, le, uint32(0))
	binary.Write(buf, le, uint32(0))
	binary.Write(buf, le, uint32(0))

	if hasSyms {
		binary.Write(buf, le, uint32(lcSymtab))
		binary.Write(buf, le, uint32(symtabCmdLen))
		binary.Write(buf, le, symoff)
		binary.Write(buf, le, uint32(len(syms)))
		binary.Write(buf, le, stroff)
		binary.Write(buf, le, uint32(len(strtab)))
	}

	buf.Write(text)
	if hasSyms {
		buf.Write(symEntries.Bytes())
		buf.Write(strtab)
	}
	return buf.Bytes()
}

func TestPELoaderAmd64(t *testing.T) {
	const imageBase = 0x140000000
	const textRVA = 0x1000
	data := buildPE32Plus(t, imageFileMachineAMD64, gadgetText, textRVA, imageBase)

	bin, err := newPE(data, "")
	if err != nil {
		t.Fatalf("newPE: %v", err)
	}
	if bin.Format() != "PE" {
		t.Errorf("Format = %q, want PE", bin.Format())
	}
	if got := bin.Arch().Name(); got != "x86-64" {
		t.Errorf("Arch = %q, want x86-64", got)
	}
	secs := bin.ExecSections()
	if len(secs) != 1 {
		t.Fatalf("ExecSections len = %d, want 1", len(secs))
	}
	s := secs[0]
	if s.Name != ".text" {
		t.Errorf("section name = %q, want .text", s.Name)
	}
	if s.Vaddr != imageBase+textRVA {
		t.Errorf("vaddr = %#x, want %#x", s.Vaddr, uint64(imageBase+textRVA))
	}
	if !bytes.Equal(s.Opcodes, gadgetText) {
		t.Errorf("opcodes mismatch: got %x", s.Opcodes)
	}
}

func TestPELoaderBaseIsNoOpForVaddr(t *testing.T) {
	// Mirrors rop3's installed pefile: relocate_image does not rebase
	// ImageBase, so --base must not shift PE vaddrs.
	const imageBase = 0x140000000
	data := buildPE32Plus(t, imageFileMachineAMD64, gadgetText, 0x1000, imageBase)
	noBase, err := newPE(data, "")
	if err != nil {
		t.Fatal(err)
	}
	withBase, err := newPE(data, "0x1000")
	if err != nil {
		t.Fatal(err)
	}
	if noBase.ExecSections()[0].Vaddr != withBase.ExecSections()[0].Vaddr {
		t.Errorf("PE --base changed vaddr: %#x vs %#x",
			noBase.ExecSections()[0].Vaddr, withBase.ExecSections()[0].Vaddr)
	}
}

func TestMachOLoaderThinX8664(t *testing.T) {
	const textAddr = 0x100000000
	const cpuX86_64 = 0x01000007
	syms := []Symbol{{Addr: textAddr, Name: "_g_one"}, {Addr: textAddr + 6, Name: "_g_two"}}
	data := buildThinMachO(t, cpuX86_64, gadgetText, textAddr, syms)

	bin, err := newMachO(data, "", "")
	if err != nil {
		t.Fatalf("newMachO: %v", err)
	}
	if bin.Format() != "Mach-O" {
		t.Errorf("Format = %q, want Mach-O", bin.Format())
	}
	if got := bin.Arch().Name(); got != "x86-64" {
		t.Errorf("Arch = %q, want x86-64", got)
	}
	secs := bin.ExecSections()
	if len(secs) != 1 {
		t.Fatalf("ExecSections len = %d, want 1", len(secs))
	}
	if secs[0].Name != "__text" {
		t.Errorf("section name = %q, want __text", secs[0].Name)
	}
	if secs[0].Vaddr != textAddr {
		t.Errorf("vaddr = %#x, want %#x", secs[0].Vaddr, uint64(textAddr))
	}
	if !bytes.Equal(secs[0].Opcodes, gadgetText) {
		t.Errorf("opcodes mismatch: got %x", secs[0].Opcodes)
	}
	got := bin.Symbols()
	if len(got) != 2 {
		t.Fatalf("Symbols len = %d, want 2 (%v)", len(got), got)
	}
}

func TestMachOLoaderBaseDelta(t *testing.T) {
	const textAddr = 0x100000000
	const cpuX86_64 = 0x01000007
	data := buildThinMachO(t, cpuX86_64, gadgetText, textAddr, nil)
	bin, err := newMachO(data, "0x2000", "")
	if err != nil {
		t.Fatal(err)
	}
	// image base is textAddr; delta = 0x2000 - textAddr; vaddr = addr + delta = 0x2000.
	if got := bin.ExecSections()[0].Vaddr; got != 0x2000 {
		t.Errorf("rebased vaddr = %#x, want 0x2000", got)
	}
}
