package binfmt

import (
	"fmt"
	"sort"
	"strings"

	"github.com/reverseame/rop4/internal/arch"
)

// rawArchs maps a --arch name to an Arch factory. x86/x86-64 are wired now;
// aarch64/riscv are added with their arch implementations (breadth wave).
var rawArchs = map[string]func() arch.Arch{
	"x86": arch.NewX86, "i386": arch.NewX86, "x86_32": arch.NewX86,
	"x86_64": arch.NewX64, "x64": arch.NewX64, "amd64": arch.NewX64,
	"aarch64": arch.NewAArch64, "arm64": arch.NewAArch64,
	"riscv64":  func() arch.Arch { return arch.NewRISCV(false) },
	"riscv64c": func() arch.Arch { return arch.NewRISCV(true) },
}

type rawBin struct {
	arch arch.Arch
	data []byte
	base uint64
}

func newRaw(data []byte, base, archName string) (Binary, error) {
	if archName == "" {
		return nil, fmt.Errorf("Raw: --arch is required for raw binaries (choose from %s)", rawArchNames())
	}
	factory, ok := rawArchs[strings.ToLower(archName)]
	if !ok {
		return nil, fmt.Errorf("Raw: unsupported --arch %s (choose from %s)", archName, rawArchNames())
	}
	v, _, err := parseAddr(base)
	if err != nil {
		return nil, err
	}
	return &rawBin{arch: factory(), data: data, base: v}, nil
}

func rawArchNames() string {
	names := make([]string, 0, len(rawArchs))
	for k := range rawArchs {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func (b *rawBin) Format() string  { return "Raw" }
func (b *rawBin) Arch() arch.Arch { return b.arch }
func (b *rawBin) ExecSections() []Section {
	return []Section{{Name: "raw", Vaddr: b.base, Opcodes: b.data}}
}
func (b *rawBin) Symbols() []Symbol     { return nil }
func (b *rawBin) Info() map[string]any  { return map[string]any{"format": "Raw", "image_base": b.base} }
