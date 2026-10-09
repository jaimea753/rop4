package arch

import (
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// Register tables ported from rop3/archs/x86_arch.py.

type subReg struct {
	name string
	size int
}

var x86regs = map[string][]subReg{
	"rax": {{"eax", 4}, {"ax", 2}, {"ah", 1}, {"al", 1}},
	"rbx": {{"ebx", 4}, {"bx", 2}, {"bh", 1}, {"bl", 1}},
	"rcx": {{"ecx", 4}, {"cx", 2}, {"ch", 1}, {"cl", 1}},
	"rdx": {{"edx", 4}, {"dx", 2}, {"dh", 1}, {"dl", 1}},
	"rsi": {{"esi", 4}, {"si", 2}, {"sil", 1}},
	"rdi": {{"edi", 4}, {"di", 2}, {"dil", 1}},
	"rsp": {{"esp", 4}, {"sp", 2}, {"spl", 1}},
	"rbp": {{"ebp", 4}, {"bp", 2}, {"bpl", 1}},
	"r8":  {{"r8d", 4}, {"r8w", 2}, {"r8b", 1}},
	"r9":  {{"r9d", 4}, {"r9w", 2}, {"r9b", 1}},
	"r10": {{"r10d", 4}, {"r10w", 2}, {"r10b", 1}},
	"r11": {{"r11d", 4}, {"r11w", 2}, {"r11b", 1}},
	"r12": {{"r12d", 4}, {"r12w", 2}, {"r12b", 1}},
	"r13": {{"r13d", 4}, {"r13w", 2}, {"r13b", 1}},
	"r14": {{"r14d", 4}, {"r14w", 2}, {"r14b", 1}},
	"r15": {{"r15d", 4}, {"r15w", 2}, {"r15b", 1}},
}

type aliasEntry struct {
	canon string
	size  int
}

// x86aliases: name -> (canonical 64-bit reg, width). Includes each canonical.
var x86aliases = map[string]aliasEntry{}

// x86byWidth: canonical -> {width: name} for widths 4 and 8.
var x86byWidth = map[string]map[int]string{}

func init() {
	for canon, subs := range x86regs {
		x86aliases[canon] = aliasEntry{canon, 8}
		x86byWidth[canon] = map[int]string{8: canon}
		for _, s := range subs {
			x86aliases[s.name] = aliasEntry{canon, s.size}
			if s.size == 4 || s.size == 8 {
				x86byWidth[canon][s.size] = s.name
			}
		}
	}
}

var x86prefixes = []string{"notrack", "bnd"}

var x86unconditional = []string{"jmp", "call", "ret", "retf"}

var x86conditional = []string{
	"je", "jne", "jz", "jnz",
	"jg", "jge", "jl", "jle",
	"ja", "jae", "jb", "jbe",
	"jo", "jno", "js", "jns",
	"jp", "jnp",
	"jcxz", "jecxz", "jrcxz",
	"loop", "loope", "loopne",
}

var x86StackLoadMnemonics = []string{"mov", "movzx", "movsx", "movsxd"}

// X86 is 32-bit x86. X64 embeds it and overrides width-dependent members.
type X86 struct {
	base
	canonicalWidth int
}

// NewX86 builds a 32-bit x86 architecture.
func NewX86() Arch { a := &X86{canonicalWidth: 4}; return Init(a) }

func (a *X86) Name() string            { return "x86" }
func (a *X86) CSArch() disasm.Arch     { return disasm.ArchX86 }
func (a *X86) CSMode() disasm.Mode     { return disasm.Mode32 }
func (a *X86) AddressSize() int        { return 4 }
func (a *X86) Alignment() int          { return 1 }
func (a *X86) DefaultDepth() int       { return 5 }
func (a *X86) SP() string              { return "esp" }
func (a *X86) BP() string              { return "ebp" }
func (a *X86) Flags() string           { return "eflags" }

func (a *X86) ROPTerminationMnemonics() []string      { return []string{"ret"} }
func (a *X86) JOPTerminationMnemonics() []string      { return []string{"jmp", "call"} }
func (a *X86) UnconditionalBranchMnemonics() []string { return x86unconditional }
func (a *X86) ConditionalBranchMnemonics() []string   { return x86conditional }
func (a *X86) MnemonicPrefixes() []string             { return x86prefixes }

// ropTerminationsFor adds retf when far-returns are requested (x86 only).
func (a *X86) ropTerminationsFor(includeRetf bool) []string {
	if includeRetf {
		return []string{"ret", "retf"}
	}
	return []string{"ret"}
}

func (a *X86) hasRetImm(decodes []*Insn, terminations []string) bool {
	for _, ins := range decodes {
		if containsStr(terminations, a.BaseMnemonic(ins.Mnemonic)) && len(ins.Operands) > 0 {
			return true
		}
	}
	return false
}

func (a *X86) IsValidJOPLast(insn *Insn) bool {
	return len(insn.Operands) > 0 && insn.Operands[0].Type != disasm.OpImm
}

func (a *X86) GetROPTerminations(includeRetf, includeRetImm bool) []search.Termination {
	ret := []search.Termination{{Pattern: []search.ByteClass{search.Fixed(0xc3)}, Size: 1}} // ret
	if includeRetImm {
		ret = append(ret, search.Termination{Pattern: []search.ByteClass{search.Fixed(0xc2), search.AnyByte(), search.AnyByte()}, Size: 3}) // ret imm
	}
	if includeRetf {
		ret = append(ret, search.Termination{Pattern: []search.ByteClass{search.Fixed(0xcb)}, Size: 1}) // retf
		if includeRetImm {
			ret = append(ret, search.Termination{Pattern: []search.ByteClass{search.Fixed(0xca), search.AnyByte(), search.AnyByte()}, Size: 3})
		}
	}
	return ret
}

func (a *X86) GetJOPTerminations() []search.Termination {
	return []search.Termination{
		{Pattern: []search.ByteClass{search.Fixed(0xff), search.OneOf(0x20, 0x21, 0x22, 0x23, 0x26, 0x27)}, Size: 2},
		{Pattern: []search.ByteClass{search.Fixed(0xff), search.OneOf(0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe6, 0xe7)}, Size: 2},
		{Pattern: []search.ByteClass{search.Fixed(0xff), search.OneOf(0x10, 0x11, 0x12, 0x13, 0x16, 0x17)}, Size: 2},
		{Pattern: []search.ByteClass{search.Fixed(0xff), search.OneOf(0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd6, 0xd7)}, Size: 2},
	}
}

func (a *X86) FirstInsnHasComplexMem(decodes []*Insn) bool {
	for _, op := range decodes[0].Operands {
		if op.Type == disasm.OpMem && op.Mem.Index != 0 {
			return true
		}
	}
	return false
}

func (a *X86) FirstInsnHasSegmentOverride(decodes []*Insn) bool {
	for _, op := range decodes[0].Operands {
		if op.Type == disasm.OpMem && op.Mem.Segment != 0 {
			return true
		}
	}
	return false
}

func (a *X86) IsReturn(insn *Insn) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	return m == "ret" || m == "retf"
}

func (a *X86) IsStackPivot(insn *Insn) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	if m == "leave" {
		return true
	}
	if m == "push" {
		return false
	}
	return a.base.IsStackPivot(insn)
}

func (a *X86) IsPCRegWrite(insn *Insn) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	if m == "ret" || m == "retf" {
		return true
	}
	if m == "jmp" {
		return len(insn.Operands) > 0 && insn.Operands[0].Type == disasm.OpReg
	}
	return false
}

func (a *X86) RopblockBranchReg(insn *Insn) (string, bool) {
	m := a.BaseMnemonic(insn.Mnemonic)
	if m == "ret" || m == "retf" {
		return "", false // self-framing
	}
	if m == "jmp" {
		ops := insn.Operands
		if len(ops) > 0 && ops[0].Type == disasm.OpReg {
			return a.self().NormalizeReg(ops[0].RegName), true
		}
	}
	return "", false
}

func (a *X86) IsStackLoad(insn *Insn, reg string) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	ops := insn.Operands
	self := a.self()
	if m == "pop" {
		return len(ops) > 0 && ops[0].Type == disasm.OpReg &&
			self.NormalizeReg(ops[0].RegName) == reg
	}
	if containsStr(x86StackLoadMnemonics, m) && len(ops) >= 2 &&
		ops[0].Type == disasm.OpReg && ops[1].Type == disasm.OpMem {
		mem := ops[1].Mem
		return mem.Base != 0 && mem.Index == 0 &&
			self.NormalizeReg(mem.BaseName) == self.NormalizeReg(a.self().SP()) &&
			self.NormalizeReg(ops[0].RegName) == reg
	}
	return false
}

func (a *X86) ClobbersReg(insn *Insn, reg string) bool {
	self := a.self()
	touches := func(getter func(*Insn) map[string]bool) bool {
		for n := range getter(insn) {
			if n != "" && self.NormalizeReg(n) == reg {
				return true
			}
		}
		return false
	}
	return touches(self.WrittenRegisters) && !touches(self.ReadRegisters)
}

func (a *X86) NormalizeReg(name string) string {
	entry, ok := x86aliases[name]
	if !ok {
		return name
	}
	if byW, ok := x86byWidth[entry.canon]; ok {
		if n, ok := byW[a.canonicalWidth]; ok {
			return n
		}
	}
	return entry.canon
}

func (a *X86) ConcreteRegEqual(x, y string) bool {
	return x86regKey(x) == x86regKey(y)
}

func x86regKey(name string) string {
	if e, ok := x86aliases[name]; ok {
		return e.canon + "/" + itoa(e.size)
	}
	return name
}

func (a *X86) IsValidAbstractReg(name string) bool {
	e, ok := x86aliases[name]
	return ok && e.size == 4
}

// X64 is x86-64.
type X64 struct{ X86 }

// NewX64 builds an x86-64 architecture.
func NewX64() Arch { a := &X64{X86{canonicalWidth: 8}}; return Init(a) }

func (a *X64) Name() string          { return "x86-64" }
func (a *X64) CSMode() disasm.Mode   { return disasm.Mode64 }
func (a *X64) AddressSize() int      { return 8 }
func (a *X64) SP() string            { return "rsp" }
func (a *X64) BP() string            { return "rbp" }
func (a *X64) Flags() string         { return "rflags" }
func (a *X64) IsValidAbstractReg(name string) bool {
	e, ok := x86aliases[name]
	return ok && e.size == 8
}

func containsStr(xs []string, s string) bool { return contains(xs, s) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
