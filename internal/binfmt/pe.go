package binfmt

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"

	"github.com/reverseame/rop4/internal/arch"
)

// PE machine types (COFF header). Mirrors rop3/binaries/pe.py.
const (
	imageFileMachineI386  = 0x014c
	imageFileMachineAMD64 = 0x8664
	imageFileMachineARM64 = 0xaa64
)

// imageDirectoryEntryExport is the data-directory index of the export table.
const imageDirectoryEntryExport = 0

type peBin struct {
	f         *pe.File
	arch      arch.Arch
	imageBase uint64
}

// newPE loads a PE binary.
//
// --base handling: rop3 calls pefile.relocate_image(base). In the reference's
// installed pefile that routine only applies in-place base relocations to the
// section bytes; it does NOT overwrite OPTIONAL_HEADER.ImageBase. rop3's
// get_exec_sections/get_symbols therefore keep the original ImageBase, so a
// PE's gadget/symbol vaddrs are unaffected by --base (and for a binary without
// a relocation directory --base is a complete no-op). debug/pe cannot patch
// bytes in place, and matching rop3's addresses requires NOT shifting vaddrs,
// so PE deliberately ignores --base for addressing (parity-verified). The base
// string is still validated for a clear error on malformed input.
func newPE(data []byte, base string) (Binary, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	a, err := peArch(f)
	if err != nil {
		return nil, err
	}
	if _, _, err := parseAddr(base); err != nil {
		return nil, err
	}
	return &peBin{f: f, arch: a, imageBase: peImageBase(f)}, nil
}

func peArch(f *pe.File) (arch.Arch, error) {
	switch f.FileHeader.Machine {
	case imageFileMachineI386:
		return arch.NewX86(), nil
	case imageFileMachineAMD64:
		return arch.NewX64(), nil
	case imageFileMachineARM64:
		return arch.NewAArch64(), nil // breadth-wave arch
	}
	return nil, fmt.Errorf("PE: Unsupported architecture type in COFF header")
}

func peImageBase(f *pe.File) uint64 {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return oh.ImageBase
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	}
	return 0
}

// peDataDirectory returns the requested data directory entry (and whether the
// optional header carries one).
func peDataDirectory(f *pe.File, idx int) (pe.DataDirectory, bool) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if idx < int(oh.NumberOfRvaAndSizes) && idx < len(oh.DataDirectory) {
			return oh.DataDirectory[idx], true
		}
	case *pe.OptionalHeader32:
		if idx < int(oh.NumberOfRvaAndSizes) && idx < len(oh.DataDirectory) {
			return oh.DataDirectory[idx], true
		}
	}
	return pe.DataDirectory{}, false
}

func (b *peBin) Format() string  { return "PE" }
func (b *peBin) Arch() arch.Arch { return b.arch }

func (b *peBin) ExecSections() []Section {
	var out []Section
	for _, sec := range b.f.Sections {
		if sec.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE == 0 {
			continue
		}
		// Data() returns SizeOfRawData bytes (like pefile's get_data()).
		data, err := sec.Data()
		if err != nil {
			continue
		}
		out = append(out, Section{
			Name:    sec.Name,
			Vaddr:   b.imageBase + uint64(sec.VirtualAddress),
			Opcodes: data,
		})
	}
	return out
}

// Symbols parses the export table (names and ordinals), rebased by the same
// delta as the sections. Mirrors rop3's get_symbols, which reads
// DIRECTORY_ENTRY_EXPORT via pefile. Stripped / export-less binaries yield none.
func (b *peBin) Symbols() []Symbol {
	dir, ok := peDataDirectory(b.f, imageDirectoryEntryExport)
	if !ok || dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	exports, err := b.parseExports(dir)
	if err != nil {
		return nil
	}
	var out []Symbol
	for _, e := range exports {
		if e.address == 0 {
			continue
		}
		out = append(out, Symbol{
			Addr: b.imageBase + uint64(e.address),
			Name: e.name,
		})
	}
	return out
}

type peExport struct {
	address uint32 // function RVA
	name    string // export name, or "ordinal_N"
}

// rvaToData returns the file bytes of length n starting at RVA rva, by locating
// the section that contains the RVA (rva - VirtualAddress + raw offset).
func (b *peBin) rvaBytes(rva, n uint32) ([]byte, bool) {
	for _, sec := range b.f.Sections {
		start := sec.VirtualAddress
		// Use VirtualSize when set, else raw size, to bound membership.
		vsize := sec.VirtualSize
		if vsize == 0 {
			vsize = sec.Size
		}
		if rva < start || rva >= start+vsize {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return nil, false
		}
		off := rva - start
		if uint64(off)+uint64(n) > uint64(len(data)) {
			return nil, false
		}
		return data[off : off+n], true
	}
	return nil, false
}

// rvaCString reads a NUL-terminated string at an RVA.
func (b *peBin) rvaCString(rva uint32) (string, bool) {
	for _, sec := range b.f.Sections {
		start := sec.VirtualAddress
		vsize := sec.VirtualSize
		if vsize == 0 {
			vsize = sec.Size
		}
		if rva < start || rva >= start+vsize {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			return "", false
		}
		off := int(rva - start)
		if off >= len(data) {
			return "", false
		}
		end := off
		for end < len(data) && data[end] != 0 {
			end++
		}
		return string(data[off:end]), true
	}
	return "", false
}

// parseExports decodes the IMAGE_EXPORT_DIRECTORY and its EAT / name tables.
func (b *peBin) parseExports(dir pe.DataDirectory) ([]peExport, error) {
	const dirSize = 40
	hdr, ok := b.rvaBytes(dir.VirtualAddress, dirSize)
	if !ok {
		return nil, fmt.Errorf("PE: export directory out of range")
	}
	le := binary.LittleEndian
	ordinalBase := le.Uint32(hdr[16:])
	numFuncs := le.Uint32(hdr[20:])
	numNames := le.Uint32(hdr[24:])
	addrOfFuncs := le.Uint32(hdr[28:])
	addrOfNames := le.Uint32(hdr[32:])
	addrOfNameOrds := le.Uint32(hdr[36:])

	// Guard against pathological counts.
	if numFuncs > 1<<20 || numNames > 1<<20 {
		return nil, fmt.Errorf("PE: implausible export counts")
	}

	eat, ok := b.rvaBytes(addrOfFuncs, numFuncs*4)
	if !ok {
		return nil, fmt.Errorf("PE: export address table out of range")
	}
	funcRVA := func(i uint32) uint32 { return le.Uint32(eat[i*4:]) }

	named := make(map[uint32]bool, numNames)
	var out []peExport

	if numNames > 0 {
		names, okN := b.rvaBytes(addrOfNames, numNames*4)
		ords, okO := b.rvaBytes(addrOfNameOrds, numNames*2)
		if okN && okO {
			for i := uint32(0); i < numNames; i++ {
				fnIdx := uint32(le.Uint16(ords[i*2:]))
				if fnIdx >= numFuncs {
					continue
				}
				name, okS := b.rvaCString(le.Uint32(names[i*4:]))
				if !okS {
					continue
				}
				named[fnIdx] = true
				out = append(out, peExport{address: funcRVA(fnIdx), name: name})
			}
		}
	}

	// Unnamed (ordinal-only) exports, in function-index order.
	for i := uint32(0); i < numFuncs; i++ {
		if named[i] {
			continue
		}
		rva := funcRVA(i)
		if rva == 0 {
			continue
		}
		out = append(out, peExport{address: rva, name: fmt.Sprintf("ordinal_%d", ordinalBase+i)})
	}
	return out, nil
}

// Info mirrors rop3's PE, which exposes no get_info().
func (b *peBin) Info() map[string]any { return nil }
