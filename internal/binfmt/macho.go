package binfmt

import (
	"bytes"
	"debug/macho"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/reverseame/rop4/internal/arch"
)

// Mach-O constants mirrored from rop3/binaries/macho.py.
const (
	vmProtExecute = 0x04
	// Section flags marking code (Apple Mach-O loader.h):
	// S_ATTR_PURE_INSTRUCTIONS (0x80000000), S_ATTR_SOME_INSTRUCTIONS (0x00000400).
	sAttrPureInstructions = 0x80000000
	sAttrSomeInstructions = 0x00000400
	sInstructionAttrs     = sAttrPureInstructions | sAttrSomeInstructions
	nStab                 = 0xe0 // N_STAB: debug (STABS) symbol mask
)

// machoSupportedArchs maps a Mach-O architecture name (also the --arch value)
// to its rop4 architecture constructor. Mirrors rop3's SUPPORTED_ARCHS.
var machoSupportedArchs = map[string]func() arch.Arch{
	"x86_64": arch.NewX64,
	"i386":   arch.NewX86,
	"arm64":  arch.NewAArch64, // breadth-wave arch
}

// machoArchName returns the lowercased architecture name for a Mach-O cputype
// ("" when unknown / unsupported). arm64e shares the arm64 cputype.
func machoArchName(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "x86_64"
	case macho.Cpu386:
		return "i386"
	case macho.CpuArm64:
		return "arm64"
	}
	return ""
}

type machoBin struct {
	f         *macho.File
	arch      arch.Arch
	baseDelta int64
}

func newMachO(data []byte, base, archName string) (Binary, error) {
	f, err := selectMachOSlice(data, archName)
	if err != nil {
		return nil, err
	}
	name := machoArchName(f.Cpu)
	factory, ok := machoSupportedArchs[name]
	if !ok {
		return nil, fmt.Errorf("Mach-O: No supported architectures were found")
	}
	b := &machoBin{f: f, arch: factory()}
	v, present, err := parseAddr(base)
	if err != nil {
		return nil, err
	}
	if present {
		b.baseDelta = int64(v) - int64(b.imageBase())
	}
	return b, nil
}

// selectMachOSlice returns the Mach-O file to scan. Thin binaries parse
// directly; fat (universal) binaries pick the --arch slice, else the first
// supported slice in file order. Mirrors rop3's _select_slice.
func selectMachOSlice(data []byte, archName string) (*macho.File, error) {
	r := bytes.NewReader(data)
	fat, ferr := macho.NewFatFile(r)
	if ferr != nil {
		if errors.Is(ferr, macho.ErrNotFat) {
			f, err := macho.NewFile(r)
			if err != nil {
				return nil, err
			}
			if archName != "" {
				if err := checkRequestedArch(archName, f); err != nil {
					return nil, err
				}
			}
			return f, nil
		}
		return nil, ferr
	}

	// Collect supported slices (first occurrence per architecture).
	available := map[string]*macho.File{}
	var order []string
	for i := range fat.Arches {
		fa := &fat.Arches[i]
		name := machoArchName(fa.Cpu)
		if name == "" {
			continue
		}
		if _, seen := available[name]; !seen {
			available[name] = fa.File
			order = append(order, name)
		}
	}

	if archName != "" {
		if _, supported := machoSupportedArchs[archName]; !supported {
			return nil, fmt.Errorf("Mach-O: unsupported --arch %s (choose from %s)",
				archName, supportedArchList())
		}
		f, ok := available[archName]
		if !ok {
			present := "none"
			if len(order) > 0 {
				sorted := append([]string(nil), order...)
				sort.Strings(sorted)
				present = strings.Join(sorted, ", ")
			}
			return nil, fmt.Errorf("Mach-O: arch %s not present in binary (available: %s)",
				archName, present)
		}
		return f, nil
	}

	for i := range fat.Arches {
		if name := machoArchName(fat.Arches[i].Cpu); name != "" {
			if _, supported := machoSupportedArchs[name]; supported {
				return fat.Arches[i].File, nil
			}
		}
	}
	return nil, fmt.Errorf("Mach-O: No supported architectures were found")
}

// checkRequestedArch validates --arch against a thin binary's own architecture.
func checkRequestedArch(archName string, f *macho.File) error {
	if _, supported := machoSupportedArchs[archName]; !supported {
		return fmt.Errorf("Mach-O: unsupported --arch %s (choose from %s)",
			archName, supportedArchList())
	}
	if name := machoArchName(f.Cpu); name != archName {
		present := name
		if present == "" {
			present = "none"
		}
		return fmt.Errorf("Mach-O: arch %s not present in binary (available: %s)", archName, present)
	}
	return nil
}

func supportedArchList() string {
	names := make([]string, 0, len(machoSupportedArchs))
	for k := range machoSupportedArchs {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// imageBase is the link-time base of the image: the __TEXT segment vmaddr
// (falling back to the lowest segment vmaddr). Mirrors rop3's _image_base.
func (b *machoBin) imageBase() uint64 {
	var vmaddrs []uint64
	for _, l := range b.f.Loads {
		seg, ok := l.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Name == "__TEXT" {
			return seg.Addr
		}
		vmaddrs = append(vmaddrs, seg.Addr)
	}
	if len(vmaddrs) == 0 {
		return 0
	}
	min := vmaddrs[0]
	for _, v := range vmaddrs[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

func (b *machoBin) Format() string  { return "Mach-O" }
func (b *machoBin) Arch() arch.Arch { return b.arch }

func (b *machoBin) ExecSections() []Section {
	var out []Section
	for _, l := range b.f.Loads {
		seg, ok := l.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Prot&vmProtExecute == 0 {
			continue
		}
		for _, sec := range b.f.Sections {
			if sec.Seg != seg.Name {
				continue
			}
			// Skip data sections living in an executable segment
			// (e.g. __const, __cstring, __unwind_info).
			if sec.Flags&sInstructionAttrs == 0 {
				continue
			}
			data, err := sec.Data()
			if err != nil {
				continue
			}
			out = append(out, Section{
				Name:    sec.Name,
				Vaddr:   uint64(int64(sec.Addr) + b.baseDelta),
				Opcodes: data,
			})
		}
	}
	return out
}

// Symbols reads the LC_SYMTAB entries, rebased by the same delta as the
// sections. Skips debug (STABS) entries and zero-address symbols. Mirrors
// rop3's get_symbols; debug/macho parses the nlist array for us.
func (b *machoBin) Symbols() []Symbol {
	if b.f.Symtab == nil {
		return nil
	}
	var out []Symbol
	for _, s := range b.f.Symtab.Syms {
		if s.Type&nStab != 0 {
			continue
		}
		if s.Value == 0 {
			continue
		}
		if s.Name == "" {
			continue
		}
		out = append(out, Symbol{Addr: uint64(int64(s.Value) + b.baseDelta), Name: s.Name})
	}
	return out
}

// Info mirrors rop3's Mach-O, which exposes no get_info().
func (b *machoBin) Info() map[string]any { return nil }
