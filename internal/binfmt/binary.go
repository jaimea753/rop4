// Package binfmt loads executable binaries and exposes their executable
// sections, architecture, and symbols. It ports rop3/binary.py and
// rop3/binaries/* onto Go's stdlib debug/elf, debug/pe, debug/macho.
package binfmt

import (
	"fmt"
	"strconv"

	"github.com/reverseame/rop4/internal/arch"
)

// Section is one executable section at a virtual address.
type Section struct {
	Name    string
	Vaddr   uint64
	Opcodes []byte
}

// Symbol is a named address.
type Symbol struct {
	Addr uint64
	Name string
}

// Binary is the loader interface (rop3's duck-typed format modules).
type Binary interface {
	Format() string
	Arch() arch.Arch
	ExecSections() []Section
	Symbols() []Symbol    // nil when the format has none / is stripped
	Info() map[string]any // nil when the format exposes none
}

// Load detects the format by magic bytes (or uses Raw when raw is set) and
// returns a Binary. base is a hex/decimal string ("" for none); archName picks
// a fat Mach-O slice or the architecture of a raw dump.
func Load(data []byte, base string, archName string, raw bool) (Binary, error) {
	if raw {
		return newRaw(data, base, archName)
	}
	switch {
	case len(data) >= 2 && data[0] == 0x4d && data[1] == 0x5a: // MZ
		return newPE(data, base)
	case len(data) >= 2 && data[0] == 0x7f && data[1] == 0x45: // \x7fE
		return newELF(data, base)
	case isMachOMagic(data):
		return newMachO(data, base, archName)
	default:
		return nil, fmt.Errorf("format file not supported")
	}
}

func isMachOMagic(d []byte) bool {
	if len(d) < 4 {
		return false
	}
	m := [4]byte{d[0], d[1], d[2], d[3]}
	for _, magic := range [][4]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe},
	} {
		if m == magic {
			return true
		}
	}
	return false
}

// parseAddr parses a base-0 integer string ("" -> 0, ok=false).
func parseAddr(s string) (uint64, bool, error) {
	if s == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(normalizeHex(s), 0, 64)
	if err != nil {
		// try signed for completeness
		sv, serr := strconv.ParseInt(normalizeHex(s), 0, 64)
		if serr != nil {
			return 0, false, fmt.Errorf("invalid address %q", s)
		}
		return uint64(sv), true, nil
	}
	return v, true, nil
}

func normalizeHex(s string) string { return s }
