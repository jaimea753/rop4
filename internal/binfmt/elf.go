package binfmt

import (
	"bytes"
	"debug/elf"
	"fmt"

	"github.com/reverseame/rop4/internal/arch"
)

// EF_RISCV_RVC marks the compressed extension in the RISC-V ELF flags.
const efRISCVRVC = 0x1

type elfBin struct {
	f         *elf.File
	arch      arch.Arch
	baseDelta int64
}

// elfFlags reads e_flags from the raw header (debug/elf does not expose it).
func elfFlags(data []byte, f *elf.File) uint32 {
	var off int
	switch f.Class {
	case elf.ELFCLASS64:
		off = 48
	case elf.ELFCLASS32:
		off = 36
	default:
		return 0
	}
	if len(data) < off+4 {
		return 0
	}
	return f.ByteOrder.Uint32(data[off : off+4])
}

func newELF(data []byte, base string) (Binary, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	a, err := elfArch(f, elfFlags(data, f))
	if err != nil {
		return nil, err
	}
	b := &elfBin{f: f, arch: a}
	delta, err := b.baseDeltaFor(base)
	if err != nil {
		return nil, err
	}
	b.baseDelta = delta
	return b, nil
}

func elfArch(f *elf.File, eflags uint32) (arch.Arch, error) {
	switch f.Machine {
	case elf.EM_X86_64, elf.EM_386:
		if f.Class == elf.ELFCLASS32 {
			return arch.NewX86(), nil
		}
		return arch.NewX64(), nil
	case elf.EM_RISCV:
		if f.Class == elf.ELFCLASS32 {
			return nil, fmt.Errorf("ELF: RV32 is not supported yet")
		}
		compressed := eflags&efRISCVRVC != 0
		return arch.NewRISCV(compressed), nil // breadth-wave arch
	case elf.EM_AARCH64:
		return arch.NewAArch64(), nil // breadth-wave arch
	}
	return nil, fmt.Errorf("ELF: Unsupported architecture type")
}

func (b *elfBin) imageBase() uint64 {
	if b.f.Type == elf.ET_DYN {
		return 0
	}
	var loads []uint64
	for _, p := range b.f.Progs {
		if p.Type == elf.PT_LOAD {
			loads = append(loads, p.Vaddr)
		}
	}
	if len(loads) == 0 {
		return 0
	}
	min := loads[0]
	for _, v := range loads[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

func (b *elfBin) baseDeltaFor(base string) (int64, error) {
	v, ok, err := parseAddr(base)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return int64(v) - int64(b.imageBase()), nil
}

func (b *elfBin) Format() string  { return "ELF" }
func (b *elfBin) Arch() arch.Arch { return b.arch }

func (b *elfBin) ExecSections() []Section {
	var out []Section
	for _, sec := range b.f.Sections {
		if sec.Flags&elf.SHF_EXECINSTR == 0 {
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
	return out
}

func (b *elfBin) Symbols() []Symbol {
	var out []Symbol
	add := func(syms []elf.Symbol) {
		for _, s := range syms {
			if s.Name != "" && s.Value != 0 {
				out = append(out, Symbol{Addr: uint64(int64(s.Value) + b.baseDelta), Name: s.Name})
			}
		}
	}
	if syms, err := b.f.Symbols(); err == nil {
		add(syms)
	}
	if syms, err := b.f.DynamicSymbols(); err == nil {
		add(syms)
	}
	return out
}

func (b *elfBin) Info() map[string]any {
	h := b.f.FileHeader
	class := 32
	if b.f.Class == elf.ELFCLASS64 {
		class = 64
	}
	endian := "little"
	if b.f.ByteOrder.String() == "BigEndian" {
		endian = "big"
	}
	return map[string]any{
		"format":     fmt.Sprintf("ELF%d", class),
		"endianness": endian,
		"machine":    h.Machine.String(),
		"type":       h.Type.String(),
		"entry":      uint64(int64(b.f.Entry) + b.baseDelta),
		"image_base": uint64(int64(b.imageBase()) + b.baseDelta),
	}
}
