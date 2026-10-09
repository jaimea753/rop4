// Package arch abstracts the per-architecture knowledge rop4 needs: how a
// gadget legitimately terminates, which instructions may not appear inside a
// gadget, register normalization, and the search strategy that fits the ISA.
//
// It ports rop3's rop3/arch.py (the Architecture ABC) and rop3/archs/*. rop3
// used a process-global `arch_singleton`; rop4 threads an explicit Arch value
// instead (one architecture per run), which removes global mutable state and
// keeps the parallel scan safe.
package arch

import (
	"strings"

	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// Insn is the decoded-instruction type arch predicates operate on.
type Insn = disasm.Insn

// Arch is the behavioral surface of one architecture. Concrete architectures
// embed *base (which supplies the shared template algorithms) and override the
// ISA-specific hooks. base dispatches through the Self back-reference so an
// override is seen by the shared algorithms, mirroring Python's self-dispatch.
type Arch interface {
	// Identity / capstone descriptors.
	Name() string
	CSArch() disasm.Arch
	CSMode() disasm.Mode
	AddressSize() int // pointer width in bytes
	Alignment() int   // minimum instruction alignment in bytes
	DefaultDepth() int

	// Mnemonic classification.
	ROPTerminationMnemonics() []string
	JOPTerminationMnemonics() []string
	UnconditionalBranchMnemonics() []string
	ConditionalBranchMnemonics() []string
	MnemonicPrefixes() []string
	BaseMnemonic(mnemonic string) string

	// Byte-pattern terminations fed to the backward scan.
	GetROPTerminations(includeRetf, includeRetImm bool) []search.Termination
	GetJOPTerminations() []search.Termination

	// Scan yields this architecture's gadgets within one executable section.
	// The default is the Galileo backward walk; fixed-width ISAs override it.
	Scan(opcodes []byte, baseVaddr uint64, depth int, dis search.DisasmFunc,
		isValidGadget func([]*Insn) bool, terminations []search.Termination,
		acceptCandidate func(uint64, []byte) bool, framed, ropblock bool,
		acceptDecodes func([]*Insn) bool) []search.Match

	// Gadget validity (template algorithms live on base).
	IsValidROPGadget(decodes []*Insn, allowUndeterministic, allowRetImm, includeRetf bool) bool
	IsValidJOPGadget(decodes []*Insn, allowUndeterministic bool) bool

	// Overridable validity hooks.
	terminatesROP(insn *Insn, terminations []string) bool
	hasRetImm(decodes []*Insn, terminations []string) bool
	IsValidJOPLast(insn *Insn) bool

	// Registers.
	SP() string
	BP() string
	Flags() string // "" when the arch has no flags register
	NormalizeReg(name string) string
	ConcreteRegEqual(a, b string) bool
	IsValidAbstractReg(name string) bool
	WrittenRegisters(insn *Insn) map[string]bool
	ReadRegisters(insn *Insn) map[string]bool

	// Memory-operand gating on the first instruction.
	FirstInsnHasComplexMem(decodes []*Insn) bool
	FirstInsnHasSegmentOverride(decodes []*Insn) bool

	// Control-flow / framing.
	IsReturn(insn *Insn) bool
	IsStackPivot(insn *Insn) bool
	RestoresReturnAddress(insn *Insn) bool
	SplitsGadget(insn *Insn) bool

	// Ropblock (abstract-gadget) predicates.
	IsPCRegWrite(insn *Insn) bool
	RopblockBranchReg(insn *Insn) (reg string, ok bool)
	IsStackLoad(insn *Insn, reg string) bool
	ClobbersReg(insn *Insn, reg string) bool

	// Reporting.
	ScanName(ropblock, framed bool) string
	Parallelizable() bool

	// self returns the outermost Arch (for base's internal dispatch).
	self() Arch
	setSelf(Arch)
}

// base holds the shared template algorithms. Concrete architectures embed it.
type base struct {
	outer Arch
}

func (b *base) self() Arch       { return b.outer }
func (b *base) setSelf(a Arch)   { b.outer = a }

// Init wires the self back-reference. Call it on every constructed Arch.
func Init(a Arch) Arch {
	a.setSelf(a)
	return a
}

// --- shared defaults -------------------------------------------------------

func (b *base) MnemonicPrefixes() []string { return nil }

func (b *base) BaseMnemonic(mnemonic string) string {
	prefixes := b.outer.MnemonicPrefixes()
	for _, part := range strings.Fields(mnemonic) {
		if !contains(prefixes, part) {
			return part
		}
	}
	return mnemonic
}

func (b *base) hasRetImm(decodes []*Insn, terminations []string) bool { return false }

func (b *base) terminatesROP(insn *Insn, terminations []string) bool {
	return contains(terminations, b.outer.BaseMnemonic(insn.Mnemonic))
}

func (b *base) IsValidJOPLast(insn *Insn) bool { return true }

func (b *base) ropTerminations(includeRetf bool) []string {
	return b.outer.ROPTerminationMnemonics()
}

// IsValidROPGadget ports Architecture.is_valid_rop_gadget.
func (b *base) IsValidROPGadget(decodes []*Insn, allowUndeterministic, allowRetImm, includeRetf bool) bool {
	if len(decodes) == 0 {
		return false
	}
	var terminations []string
	if o, ok := b.outer.(interface{ ropTerminationsFor(bool) []string }); ok {
		terminations = o.ropTerminationsFor(includeRetf)
	} else {
		terminations = b.outer.ROPTerminationMnemonics()
	}
	if !b.outer.terminatesROP(decodes[len(decodes)-1], terminations) {
		return false
	}
	if !allowRetImm && b.outer.hasRetImm(decodes, terminations) {
		return false
	}
	inter := decodes[:len(decodes)-1]
	for _, ins := range inter {
		m := b.outer.BaseMnemonic(ins.Mnemonic)
		if contains(terminations, m) {
			return false
		}
		if contains(b.outer.UnconditionalBranchMnemonics(), m) {
			return false
		}
	}
	if !allowUndeterministic {
		for _, ins := range inter {
			if contains(b.outer.ConditionalBranchMnemonics(), b.outer.BaseMnemonic(ins.Mnemonic)) {
				return false
			}
		}
	}
	return true
}

// IsValidJOPGadget ports Architecture.is_valid_jop_gadget.
func (b *base) IsValidJOPGadget(decodes []*Insn, allowUndeterministic bool) bool {
	if len(decodes) == 0 {
		return false
	}
	terminations := b.outer.JOPTerminationMnemonics()
	last := decodes[len(decodes)-1]
	if !contains(terminations, b.outer.BaseMnemonic(last.Mnemonic)) {
		return false
	}
	if !b.outer.IsValidJOPLast(last) {
		return false
	}
	inter := decodes[:len(decodes)-1]
	for _, ins := range inter {
		if contains(b.outer.UnconditionalBranchMnemonics(), b.outer.BaseMnemonic(ins.Mnemonic)) {
			return false
		}
	}
	if !allowUndeterministic {
		for _, ins := range inter {
			if contains(b.outer.ConditionalBranchMnemonics(), b.outer.BaseMnemonic(ins.Mnemonic)) {
				return false
			}
		}
	}
	return true
}

// Scan: default Galileo backward walk (rop3 Architecture.scan default).
func (b *base) Scan(opcodes []byte, baseVaddr uint64, depth int, dis search.DisasmFunc,
	isValidGadget func([]*Insn) bool, terminations []search.Termination,
	acceptCandidate func(uint64, []byte) bool, framed, ropblock bool,
	acceptDecodes func([]*Insn) bool) []search.Match {
	// ropblock / framed handled by fixed-width overrides; base ignores them.
	return search.Galileo(opcodes, baseVaddr, terminations, depth, b.outer.Alignment(),
		dis, search.Predicates{
			IsValidGadget:         isValidGadget,
			AcceptCandidate:       acceptCandidate,
			RestoresReturnAddress: b.outer.RestoresReturnAddress,
		})
}

func (b *base) Name() string                 { return "arch" }
func (b *base) ScanName(ropblock, framed bool) string {
	if ropblock {
		return "ropblock"
	}
	return "galileo"
}
func (b *base) Parallelizable() bool { return true }

func (b *base) MnemonicPrefixesDefault() []string { return nil }
func (b *base) Flags() string                     { return "" }

func (b *base) NormalizeReg(name string) string { return name }
func (b *base) ConcreteRegEqual(a, c string) bool {
	return b.outer.NormalizeReg(a) == b.outer.NormalizeReg(c)
}

func (b *base) FirstInsnHasComplexMem(decodes []*Insn) bool      { return false }
func (b *base) FirstInsnHasSegmentOverride(decodes []*Insn) bool { return false }

func (b *base) IsReturn(insn *Insn) bool { return false }

// IsStackPivot default: an explicit stack-pointer destination operand.
func (b *base) IsStackPivot(insn *Insn) bool {
	if len(insn.Operands) == 0 || insn.Operands[0].Type != disasm.OpReg {
		return false
	}
	return b.outer.NormalizeReg(insn.Operands[0].RegName) == b.outer.NormalizeReg(b.outer.SP())
}

func (b *base) RestoresReturnAddress(insn *Insn) bool { return false }

func (b *base) SplitsGadget(insn *Insn) bool {
	return contains(b.outer.UnconditionalBranchMnemonics(), b.outer.BaseMnemonic(insn.Mnemonic))
}

func (b *base) IsPCRegWrite(insn *Insn) bool              { return false }
func (b *base) RopblockBranchReg(insn *Insn) (string, bool) { return "", false }
func (b *base) IsStackLoad(insn *Insn, reg string) bool   { return false }
func (b *base) ClobbersReg(insn *Insn, reg string) bool   { return false }

// WrittenRegisters / ReadRegisters: default use capstone's regs_access
// (resolved to names in the disasm layer); when unavailable (RegsOK false),
// return empty and let the arch override derive from the encoding.
func (b *base) WrittenRegisters(insn *Insn) map[string]bool {
	out := map[string]bool{}
	if insn.RegsOK {
		for _, n := range insn.RegsWrittenNames {
			if n != "" {
				out[n] = true
			}
		}
	}
	return out
}

func (b *base) ReadRegisters(insn *Insn) map[string]bool {
	out := map[string]bool{}
	if insn.RegsOK {
		for _, n := range insn.RegsReadNames {
			if n != "" {
				out[n] = true
			}
		}
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
