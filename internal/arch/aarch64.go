package arch

import (
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// AArch64 (ARM64) support, ported from rop3/archs/aarch64_arch.py. It is a
// fixed-width (every instruction is 4 bytes), naturally 4-byte-aligned ISA, so
// gadgets can only begin on instruction boundaries and the aligned linear sweep
// both suffices and is faster than Galileo (see Scan).

// aarch64Regs: ABI register names capstone prints for the 64-bit integer file.
// xzr (the hardwired zero register) is not a usable destination and is excluded.
var aarch64Regs = func() map[string]bool {
	m := map[string]bool{"sp": true, "lr": true, "fp": true}
	for i := 0; i < 31; i++ {
		m["x"+itoa(i)] = true
	}
	return m
}()

// Direct (b/bl) and indirect (br/blr) branches plus ret. All split a gadget.
var aarch64Unconditional = []string{"b", "bl", "br", "blr", "ret"}

// Indirect branches usable as JOP terminations (a ret is handled as ROP).
var aarch64JOPTerm = []string{"br", "blr"}

var aarch64Conditional = []string{
	"b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo", "b.mi", "b.pl",
	"b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le",
	"b.al", "b.nv",
	"cbz", "cbnz", "tbz", "tbnz",
}

// aarch64FullWidthAliases: alternative capstone spellings of the same 64-bit
// register (fp->x29, lr->x30, wsp->sp, wzr->xzr).
var aarch64FullWidthAliases = map[string]string{
	"fp": "x29", "lr": "x30", "wsp": "sp", "wzr": "xzr",
}

var aarch64LoadMnemonics = []string{"ldr", "ldp", "ldur"}

// AArch64 implements Arch.
type AArch64 struct{ base }

// NewAArch64 builds the AArch64 (ARM64) architecture.
func NewAArch64() Arch { return Init(&AArch64{}) }

func (a *AArch64) Name() string        { return "AArch64 (ARM64)" }
func (a *AArch64) CSArch() disasm.Arch { return disasm.ArchARM64 }
func (a *AArch64) CSMode() disasm.Mode { return disasm.ModeARM }
func (a *AArch64) AddressSize() int    { return 8 }
func (a *AArch64) Alignment() int      { return 4 }
func (a *AArch64) DefaultDepth() int   { return 20 }
func (a *AArch64) SP() string          { return "sp" }
func (a *AArch64) BP() string          { return "x29" }
func (a *AArch64) Flags() string       { return "nzcv" }
func (a *AArch64) Parallelizable() bool { return false }

func (a *AArch64) ScanName(ropblock, framed bool) string {
	if ropblock {
		return "ropblock"
	}
	if framed {
		return "framed aligned"
	}
	return "aligned"
}

func (a *AArch64) ROPTerminationMnemonics() []string      { return []string{"ret"} }
func (a *AArch64) JOPTerminationMnemonics() []string      { return aarch64JOPTerm }
func (a *AArch64) UnconditionalBranchMnemonics() []string { return aarch64Unconditional }
func (a *AArch64) ConditionalBranchMnemonics() []string   { return aarch64Conditional }

// Scan: fixed-width, naturally aligned ISA, so the aligned linear sweep finds
// the same gadgets as Galileo, faster. When framed, keep only gadgets that
// restore the return address (lr/x30) from the stack before returning.
func (a *AArch64) Scan(opcodes []byte, baseVaddr uint64, depth int, dis search.DisasmFunc,
	isValidGadget func([]*Insn) bool, terminations []search.Termination,
	acceptCandidate func(uint64, []byte) bool, framed, ropblock bool,
	acceptDecodes func([]*Insn) bool) []search.Match {
	if ropblock {
		panic("ropblock not yet implemented")
	}
	self := a.self()
	var isReturn func(*Insn) bool
	if framed {
		isReturn = self.IsReturn
	}
	return search.AlignedScan(opcodes, baseVaddr, depth, self.Alignment(), dis,
		isValidGadget, self.RestoresReturnAddress, isReturn, acceptCandidate)
}

// --- Byte-level gadget terminations (only consulted if routed through Galileo).

func (a *AArch64) GetROPTerminations(includeRetf, includeRetImm bool) []search.Termination {
	// RET Rn = 0xD65F0000 | (Rn << 5); Rn's low 3 bits sit in bits 7:5 of byte 0.
	return []search.Termination{{
		Pattern: []search.ByteClass{
			search.OneOf(0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0),
			search.OneOf(0x00, 0x01, 0x02, 0x03),
			search.Fixed(0x5f),
			search.Fixed(0xd6),
		},
		Size: 4,
	}}
}

func (a *AArch64) GetJOPTerminations() []search.Termination {
	// BR Rn = 0xD61F0000 | (Rn << 5); BLR Rn = 0xD63F0000 | (Rn << 5).
	return []search.Termination{{
		Pattern: []search.ByteClass{
			search.OneOf(0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0),
			search.OneOf(0x00, 0x01, 0x02, 0x03),
			search.OneOf(0x1f, 0x3f),
			search.Fixed(0xd6),
		},
		Size: 4,
	}}
}

// --- Control-flow / framing --------------------------------------------------

func (a *AArch64) IsReturn(insn *Insn) bool {
	return a.BaseMnemonic(insn.Mnemonic) == "ret"
}

// RestoresReturnAddress: whether insn restores the return address (lr/x30) from
// the stack, e.g. `ldr x30, [sp, #off]` or `ldp x29, x30, [sp], #off`.
func (a *AArch64) RestoresReturnAddress(insn *Insn) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	if m != "ldr" && m != "ldp" {
		return false
	}
	loadsLR, fromStack := false, false
	for _, op := range insn.Operands {
		if op.Type == disasm.OpReg && (op.RegName == "x30" || op.RegName == "lr") {
			loadsLR = true
		}
		if op.Type == disasm.OpMem && (op.Mem.BaseName == "sp" || op.Mem.BaseName == "wsp") {
			fromStack = true
		}
	}
	return loadsLR && fromStack
}

// --- Registers ---------------------------------------------------------------

func (a *AArch64) IsValidAbstractReg(name string) bool { return aarch64Regs[name] }

func aarch64Norm(name string) string {
	if c, ok := aarch64FullWidthAliases[name]; ok {
		return c
	}
	if len(name) > 1 && name[0] == 'w' && allDigits(name[1:]) {
		return "x" + name[1:]
	}
	return name
}

func aarch64IsWView(name string) bool {
	if name == "wsp" || name == "wzr" {
		return true
	}
	return len(name) > 1 && name[0] == 'w' && allDigits(name[1:])
}

func (a *AArch64) NormalizeReg(name string) string { return aarch64Norm(name) }

func (a *AArch64) ConcreteRegEqual(x, y string) bool {
	if aarch64IsWView(x) != aarch64IsWView(y) {
		return false
	}
	return aarch64Norm(x) == aarch64Norm(y)
}

// --- ropblock (abstract-gadget) predicates (deferred; ported for fidelity) ---

func (a *AArch64) IsPCRegWrite(insn *Insn) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	return m == "ret" || m == "br"
}

func (a *AArch64) RopblockBranchReg(insn *Insn) (string, bool) {
	m := a.BaseMnemonic(insn.Mnemonic)
	if m == "ret" || m == "br" {
		for _, op := range insn.Operands {
			if op.Type == disasm.OpReg {
				return aarch64Norm(op.RegName), true
			}
		}
		if m == "ret" {
			return "x30", true // bare ret branches through x30/lr
		}
	}
	return "", false
}

func (a *AArch64) IsStackLoad(insn *Insn, reg string) bool {
	if !contains(aarch64LoadMnemonics, a.BaseMnemonic(insn.Mnemonic)) {
		return false
	}
	fromStack := false
	for _, op := range insn.Operands {
		if op.Type == disasm.OpMem && (op.Mem.BaseName == "sp" || op.Mem.BaseName == "wsp") {
			fromStack = true
		}
	}
	if !fromStack {
		return false
	}
	for _, op := range insn.Operands {
		if op.Type == disasm.OpReg && aarch64Norm(op.RegName) == reg {
			return true
		}
	}
	return false
}

func (a *AArch64) ClobbersReg(insn *Insn, reg string) bool {
	self := a.self()
	touches := func(getter func(*Insn) map[string]bool) bool {
		for n := range getter(insn) {
			if n != "" && aarch64Norm(n) == reg {
				return true
			}
		}
		return false
	}
	return touches(self.WrittenRegisters) && !touches(self.ReadRegisters)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
