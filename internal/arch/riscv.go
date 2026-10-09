package arch

import (
	"strings"

	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// RISC-V (RV64I) support, ported from rop3/archs/riscv_arch.py. `compressed`
// reflects the presence of the C (compressed) extension in the binary: it both
// enables capstone's 16-bit decoding and relaxes the instruction alignment from
// 4 to 2 bytes. Capstone implements neither cs_regs_access nor per-operand
// access flags for RISC-V, so written/read registers are derived from the
// encoding (rd is always the first operand).

// riscvRegs: ABI register names capstone prints for the integer file (x0, the
// hardwired zero register, is not a usable destination and is excluded).
var riscvRegs = map[string]bool{
	"ra": true, "sp": true, "gp": true, "tp": true,
	"t0": true, "t1": true, "t2": true, "t3": true, "t4": true, "t5": true, "t6": true,
	"s0": true, "fp": true, "s1": true, "s2": true, "s3": true, "s4": true, "s5": true, "s6": true,
	"s7": true, "s8": true, "s9": true, "s10": true, "s11": true,
	"a0": true, "a1": true, "a2": true, "a3": true, "a4": true, "a5": true, "a6": true, "a7": true,
}

// Unconditional transfers. ret/jr/jalr are indirect; j/jal are direct. ret
// (capstone's spelling of `jalr x0, 0(ra)`) is listed so an intermediate return
// splits a JOP/ropblock gadget. Compressed variants share printed mnemonics.
var riscvUnconditional = []string{
	"ret",
	"j", "jal", "jalr", "jr",
	"c.j", "c.jal", "c.jalr", "c.jr",
}

// Indirect branches usable as JOP terminations (a ret is handled as ROP).
var riscvJOPTerm = []string{"jr", "jalr", "c.jr", "c.jalr"}

var riscvConditional = []string{
	"beq", "bne", "blt", "bge", "bltu", "bgeu",
	"beqz", "bnez", "blez", "bgez", "bltz", "bgtz",
	"c.beqz", "c.bnez",
}

// Store instructions: their first operand is the source register (rs2), not a
// destination -- they write memory, not a register.
var riscvStore = []string{
	"sb", "sh", "sw", "sd",
	"fsb", "fsh", "fsw", "fsd", "fsq",
	"c.sw", "c.sd", "c.swsp", "c.sdsp",
	"c.fsw", "c.fsd", "c.fswsp", "c.fsdsp",
}

// riscvNonWriting: instructions whose first register operand is read, not
// written (stores, branches, register-reading jumps).
var riscvNonWriting = func() map[string]bool {
	m := map[string]bool{"jr": true, "c.jr": true, "ret": true, "c.jalr": true}
	for _, s := range riscvStore {
		m[s] = true
	}
	for _, s := range riscvConditional {
		m[s] = true
	}
	return m
}()

// riscvLoad: integer loads. A RISC-V ROP gadget must reload ra (x1) from the
// stack before ret; the canonical restore is `ld ra, off(sp)` (or c.ldsp).
var riscvLoad = map[string]bool{
	"ld": true, "lw": true, "lwu": true, "lh": true, "lhu": true, "lb": true, "lbu": true,
	"c.ldsp": true, "c.lwsp": true, "c.ld": true, "c.lw": true,
}

// RISCV implements Arch. It is stateful: compression changes mode and alignment.
type RISCV struct {
	base
	compressed bool
}

// NewRISCV builds the RISC-V RV64 architecture (compressed enables the C ext).
func NewRISCV(compressed bool) Arch { return Init(&RISCV{compressed: compressed}) }

func (a *RISCV) Name() string {
	if a.compressed {
		return "RISC-V RV64 (compressed)"
	}
	return "RISC-V RV64"
}

func (a *RISCV) CSArch() disasm.Arch { return disasm.ArchRISCV }
func (a *RISCV) CSMode() disasm.Mode {
	m := disasm.ModeRV64
	if a.compressed {
		m |= disasm.ModeRVC
	}
	return m
}
func (a *RISCV) AddressSize() int { return 8 }
func (a *RISCV) Alignment() int {
	// Base ISA instructions are 4-byte aligned; the C extension allows 2.
	if a.compressed {
		return 2
	}
	return 4
}
func (a *RISCV) DefaultDepth() int    { return 24 }
func (a *RISCV) SP() string           { return "sp" }
func (a *RISCV) BP() string           { return "s0" }
func (a *RISCV) Flags() string        { return "" }
func (a *RISCV) Parallelizable() bool { return false }

func (a *RISCV) ScanName(ropblock, framed bool) string {
	if ropblock {
		return "ropblock"
	}
	if framed {
		return "framed aligned"
	}
	return "aligned"
}

func (a *RISCV) ROPTerminationMnemonics() []string      { return []string{"ret"} }
func (a *RISCV) JOPTerminationMnemonics() []string      { return riscvJOPTerm }
func (a *RISCV) UnconditionalBranchMnemonics() []string { return riscvUnconditional }
func (a *RISCV) ConditionalBranchMnemonics() []string   { return riscvConditional }

// Scan: ret jumps through ra, so a useful ROP gadget must first restore ra from
// the stack -- the aligned sweep gated on that frame load (the default).
// --no-frame drops the requirement (plain aligned sweep).
func (a *RISCV) Scan(opcodes []byte, baseVaddr uint64, depth int, dis search.DisasmFunc,
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

func (a *RISCV) GetROPTerminations(includeRetf, includeRetImm bool) []search.Termination {
	// ret = jalr x0, 0(ra) (0x00008067); compressed c.jr ra (0x8082).
	ret := []search.Termination{{
		Pattern: []search.ByteClass{search.Fixed(0x67), search.Fixed(0x80), search.Fixed(0x00), search.Fixed(0x00)},
		Size:    4,
	}}
	if a.compressed {
		ret = append(ret, search.Termination{
			Pattern: []search.ByteClass{search.Fixed(0x82), search.Fixed(0x80)},
			Size:    2,
		})
	}
	return ret
}

func (a *RISCV) GetJOPTerminations() []search.Termination {
	// jalr rd, imm(rs1): opcode 0b1100111 (0x67) low 7 bits -> first byte 0x67/0xe7.
	ret := []search.Termination{{
		Pattern: []search.ByteClass{search.OneOf(0x67, 0xe7), search.AnyByte(), search.AnyByte(), search.AnyByte()},
		Size:    4,
	}}
	if a.compressed {
		// c.jr/c.jalr rs1: bits[15:13]=100, bits[6:2]=0, bits[1:0]=10.
		ret = append(ret, search.Termination{
			Pattern: []search.ByteClass{search.OneOf(0x02, 0x82), search.OneOf(byteRange(0x80, 0x9f)...)},
			Size:    2,
		})
	}
	return ret
}

// --- Mnemonic classification / returns --------------------------------------

// terminatesROP: the canonical return is `ret` (jalr x0, 0(ra)). Capstone
// renders the compressed form `c.jr ra` under its own mnemonic, so recognize it
// by its target register; other `c.jr <rs>` are plain indirect jumps.
func (a *RISCV) terminatesROP(insn *Insn, terminations []string) bool {
	if insn.Mnemonic == "ret" {
		return true
	}
	return insn.Mnemonic == "c.jr" && strings.TrimSpace(insn.OpStr) == "ra"
}

func (a *RISCV) IsReturn(insn *Insn) bool {
	return a.terminatesROP(insn, a.ROPTerminationMnemonics())
}

// RestoresReturnAddress: the frame load on RISC-V is the ra restore.
func (a *RISCV) RestoresReturnAddress(insn *Insn) bool { return a.isRALoad(insn) }

// isRALoad: whether insn loads ra (x1) from the stack, e.g. `ld ra, off(sp)` or
// `c.ldsp ra, off`. Capstone renders the base sp either as a memory operand's
// base (ld) or as a bare register operand (c.ldsp).
func (a *RISCV) isRALoad(insn *Insn) bool {
	if !riscvLoad[a.BaseMnemonic(insn.Mnemonic)] {
		return false
	}
	ops := insn.Operands
	if len(ops) == 0 || ops[0].Type != disasm.OpReg || ops[0].RegName != "ra" {
		return false
	}
	for _, op := range ops[1:] {
		if op.Type == disasm.OpMem && op.Mem.BaseName == "sp" {
			return true
		}
		if op.Type == disasm.OpReg && op.RegName == "sp" {
			return true
		}
	}
	return false
}

func (a *RISCV) IsValidAbstractReg(name string) bool { return riscvRegs[name] }

// --- Registers (derived from the encoding; capstone has no reg-access) -------

// WrittenRegisters: rd is always the first operand and is written by every
// instruction except stores, branches and register-reading jumps.
func (a *RISCV) WrittenRegisters(insn *Insn) map[string]bool {
	out := map[string]bool{}
	if riscvNonWriting[a.BaseMnemonic(insn.Mnemonic)] {
		return out
	}
	ops := insn.Operands
	if len(ops) > 0 && ops[0].Type == disasm.OpReg && ops[0].RegName != "" {
		out[ops[0].RegName] = true
	}
	return out
}

// ReadRegisters: rd is the first operand and written (not read) for the ordinary
// forms; every other register operand is a source, and for the non-writing forms
// (stores, branches, register jumps) the first operand is a source too.
func (a *RISCV) ReadRegisters(insn *Insn) map[string]bool {
	out := map[string]bool{}
	regOps := make([]Operand, 0, len(insn.Operands))
	for _, op := range insn.Operands {
		if op.Type == disasm.OpReg {
			regOps = append(regOps, op)
		}
	}
	if !riscvNonWriting[a.BaseMnemonic(insn.Mnemonic)] && len(regOps) > 0 {
		regOps = regOps[1:]
	}
	for _, op := range regOps {
		if op.RegName != "" {
			out[op.RegName] = true
		}
	}
	return out
}

// Operand is re-exported locally for ReadRegisters' slice type.
type Operand = disasm.Operand

// readsReg: whether insn reads register reg (see ReadRegisters).
func (a *RISCV) readsReg(insn *Insn, reg string) bool {
	regOps := make([]Operand, 0, len(insn.Operands))
	for _, op := range insn.Operands {
		if op.Type == disasm.OpReg {
			regOps = append(regOps, op)
		}
	}
	if !riscvNonWriting[a.BaseMnemonic(insn.Mnemonic)] && len(regOps) > 0 {
		regOps = regOps[1:]
	}
	for _, op := range regOps {
		if op.RegName == reg {
			return true
		}
	}
	return false
}

// --- ropblock (abstract-gadget) predicates (deferred; ported for fidelity) ---

func (a *RISCV) IsPCRegWrite(insn *Insn) bool {
	m := a.BaseMnemonic(insn.Mnemonic)
	return m == "ret" || m == "jr" || m == "c.jr"
}

func (a *RISCV) RopblockBranchReg(insn *Insn) (string, bool) {
	if a.BaseMnemonic(insn.Mnemonic) == "ret" {
		return "ra", true
	}
	for _, op := range insn.Operands {
		if op.Type == disasm.OpReg {
			return op.RegName, true
		}
	}
	return "", false
}

func (a *RISCV) IsStackLoad(insn *Insn, reg string) bool {
	if !riscvLoad[a.BaseMnemonic(insn.Mnemonic)] {
		return false
	}
	ops := insn.Operands
	if len(ops) == 0 || ops[0].Type != disasm.OpReg || ops[0].RegName != reg {
		return false
	}
	for _, op := range ops[1:] {
		if op.Type == disasm.OpMem && op.Mem.BaseName == "sp" {
			return true
		}
		if op.Type == disasm.OpReg && op.RegName == "sp" {
			return true
		}
	}
	return false
}

func (a *RISCV) ClobbersReg(insn *Insn, reg string) bool {
	written := false
	for n := range a.WrittenRegisters(insn) {
		if n == reg {
			written = true
			break
		}
	}
	if !written {
		return false
	}
	return !a.readsReg(insn, reg)
}

// byteRange returns the inclusive byte range [lo, hi] as a slice.
func byteRange(lo, hi byte) []byte {
	out := make([]byte, 0, int(hi)-int(lo)+1)
	for b := int(lo); b <= int(hi); b++ {
		out = append(out, byte(b))
	}
	return out
}
