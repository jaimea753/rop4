// Package disasm is rop4's only CGo dependency: a thin wrapper over the
// official libcapstone v5 C library. It exposes a Go-native instruction and
// operand model so the rest of rop4 never touches C. rop3 built its entire
// semantic layer on Capstone's mnemonic/operand/register vocabulary; binding
// Capstone directly keeps that vocabulary identical.
//
// There is no official Go binding for Capstone, so this wrapper is maintained
// in-tree rather than depending on a third-party fork.
package disasm

/*
#cgo pkg-config: capstone
#include <capstone/capstone.h>
#include <stdlib.h>
#include <string.h>

// Normalized operand, arch-independent, filled from the arch-specific detail
// union by r4_fill below.
typedef struct {
	int       type;     // 1=reg, 2=imm, 3=mem, 4=other
	unsigned  reg;      // reg id for REG operands
	long long imm;      // value for IMM operands
	unsigned  segment;  // MEM: segment reg (x86 only; 0 otherwise)
	unsigned  base;     // MEM: base reg
	unsigned  index;    // MEM: index reg (x86/arm64; 0 on riscv)
	int       scale;    // MEM: index scale (x86 only; 0 otherwise)
	long long disp;     // MEM: displacement
} r4_op;

enum { R4_OP_REG = 1, R4_OP_IMM = 2, R4_OP_MEM = 3, R4_OP_OTHER = 4 };

// Extract up to maxops operands from insn into out, returning the count.
// arch selects which member of the capstone detail union to read.
static int r4_fill(int arch, cs_insn *insn, r4_op *out, int maxops) {
	if (insn->detail == NULL) return 0;
	int n = 0;
	if (arch == CS_ARCH_X86) {
		cs_x86 *d = &insn->detail->x86;
		for (int i = 0; i < d->op_count && n < maxops; i++) {
			cs_x86_op *op = &d->operands[i];
			r4_op *o = &out[n++];
			memset(o, 0, sizeof(*o));
			switch (op->type) {
			case X86_OP_REG: o->type = R4_OP_REG; o->reg = op->reg; break;
			case X86_OP_IMM: o->type = R4_OP_IMM; o->imm = op->imm; break;
			case X86_OP_MEM:
				o->type = R4_OP_MEM;
				o->segment = op->mem.segment; o->base = op->mem.base;
				o->index = op->mem.index; o->scale = op->mem.scale;
				o->disp = op->mem.disp;
				break;
			default: o->type = R4_OP_OTHER; break;
			}
		}
	} else if (arch == CS_ARCH_ARM64) {
		cs_arm64 *d = &insn->detail->arm64;
		for (int i = 0; i < d->op_count && n < maxops; i++) {
			cs_arm64_op *op = &d->operands[i];
			r4_op *o = &out[n++];
			memset(o, 0, sizeof(*o));
			switch (op->type) {
			case ARM64_OP_REG: o->type = R4_OP_REG; o->reg = op->reg; break;
			case ARM64_OP_IMM: o->type = R4_OP_IMM; o->imm = op->imm; break;
			case ARM64_OP_MEM:
				o->type = R4_OP_MEM;
				o->base = op->mem.base; o->index = op->mem.index;
				o->disp = op->mem.disp;
				break;
			default: o->type = R4_OP_OTHER; break;
			}
		}
	} else if (arch == CS_ARCH_RISCV) {
		cs_riscv *d = &insn->detail->riscv;
		for (int i = 0; i < d->op_count && n < maxops; i++) {
			cs_riscv_op *op = &d->operands[i];
			r4_op *o = &out[n++];
			memset(o, 0, sizeof(*o));
			switch (op->type) {
			case RISCV_OP_REG: o->type = R4_OP_REG; o->reg = op->reg; break;
			case RISCV_OP_IMM: o->type = R4_OP_IMM; o->imm = op->imm; break;
			case RISCV_OP_MEM:
				o->type = R4_OP_MEM;
				o->base = op->mem.base; o->disp = op->mem.disp;
				break;
			default: o->type = R4_OP_OTHER; break;
			}
		}
	}
	return n;
}

// Wrap cs_regs_access. Returns CS_ERR_OK on success. Caller sizes rd/wr to 64.
static int r4_regs(csh h, cs_insn *insn, uint16_t *rd, int *nrd, uint16_t *wr, int *nwr) {
	cs_regs r, w;
	uint8_t rc = 0, wc = 0;
	cs_err e = cs_regs_access(h, insn, r, &rc, w, &wc);
	if (e != CS_ERR_OK) return (int)e;
	for (uint8_t i = 0; i < rc; i++) rd[i] = r[i];
	for (uint8_t i = 0; i < wc; i++) wr[i] = w[i];
	*nrd = rc; *nwr = wc;
	return CS_ERR_OK;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Arch identifies a capstone architecture+mode pairing.
type Arch int
type Mode int

// Architecture constants mirror the capstone CS_ARCH_* values rop4 uses.
const (
	ArchX86   Arch = C.CS_ARCH_X86
	ArchARM64 Arch = C.CS_ARCH_ARM64
	ArchRISCV Arch = C.CS_ARCH_RISCV
)

// Mode constants (OR-able) mirror capstone CS_MODE_*.
const (
	Mode32    Mode = C.CS_MODE_32
	Mode64    Mode = C.CS_MODE_64
	ModeARM   Mode = C.CS_MODE_ARM // little-endian AArch64 (== 0)
	ModeRV64  Mode = C.CS_MODE_RISCV64
	ModeRVC   Mode = C.CS_MODE_RISCVC
)

// OpType classifies an operand.
type OpType int

const (
	OpInvalid OpType = 0
	OpReg     OpType = C.R4_OP_REG
	OpImm     OpType = C.R4_OP_IMM
	OpMem     OpType = C.R4_OP_MEM
	OpOther   OpType = C.R4_OP_OTHER
)

// Mem holds a memory operand's components (fields absent on an arch are 0).
type Mem struct {
	Segment     uint
	Base        uint
	Index       uint
	Scale       int
	Disp        int64
	SegmentName string
	BaseName    string
	IndexName   string
}

// Operand is one decoded operand.
type Operand struct {
	Type    OpType
	Reg     uint
	RegName string
	Imm     int64
	Mem     Mem
}

// Insn is a single decoded instruction, fully copied into Go memory (no C
// pointers are retained, so it stays valid after the engine advances or closes).
type Insn struct {
	ID       uint
	Address  uint64
	Mnemonic string
	OpStr    string
	Bytes    []byte
	Operands []Operand
	// RegsRead/RegsWritten come from cs_regs_access when available; RegsOK is
	// false when capstone has no reg-access for this arch (e.g. RISC-V), so
	// callers fall back to encoding-derived register sets, as rop3 does.
	RegsRead         []uint
	RegsWritten      []uint
	RegsReadNames    []string
	RegsWrittenNames []string
	RegsOK           bool
}

// Engine is an open capstone handle for one architecture+mode. Not safe for
// concurrent use; open one per goroutine.
type Engine struct {
	h    C.csh
	arch Arch
}

// Open creates an engine with detail mode on.
func Open(arch Arch, mode Mode) (*Engine, error) {
	var h C.csh
	if e := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &h); e != C.CS_ERR_OK {
		return nil, fmt.Errorf("cs_open: %s", C.GoString(C.cs_strerror(e)))
	}
	if e := C.cs_option(h, C.CS_OPT_DETAIL, C.CS_OPT_ON); e != C.CS_ERR_OK {
		C.cs_close(&h)
		return nil, fmt.Errorf("cs_option(DETAIL): %s", C.GoString(C.cs_strerror(e)))
	}
	return &Engine{h: h, arch: arch}, nil
}

// Close releases the capstone handle.
func (e *Engine) Close() {
	if e.h != 0 {
		C.cs_close(&e.h)
		e.h = 0
	}
}

// RegName returns capstone's name for a register id ("" for 0/invalid).
func (e *Engine) RegName(id uint) string {
	if id == 0 {
		return ""
	}
	return C.GoString(C.cs_reg_name(e.h, C.uint(id)))
}

// Disasm decodes up to limit instructions from code at virtual address addr
// (limit 0 means decode as many as possible). It fully materializes the
// result; use it for the small fixed windows the backward/literal scans decode.
func (e *Engine) Disasm(code []byte, addr uint64, limit int) ([]*Insn, error) {
	if len(code) == 0 {
		return nil, nil
	}
	var insn *C.cs_insn
	n := C.cs_disasm(e.h,
		(*C.uint8_t)(unsafe.Pointer(&code[0])), C.size_t(len(code)),
		C.uint64_t(addr), C.size_t(limit), &insn)
	if n == 0 {
		return nil, nil
	}
	defer C.cs_free(insn, n)
	out := make([]*Insn, 0, int(n))
	arr := unsafe.Slice(insn, int(n))
	for i := range arr {
		out = append(out, e.convert(&arr[i]))
	}
	return out, nil
}

// convert copies a C cs_insn (with detail) into a Go Insn.
func (e *Engine) convert(ci *C.cs_insn) *Insn {
	in := &Insn{
		ID:       uint(ci.id),
		Address:  uint64(ci.address),
		Mnemonic: C.GoString(&ci.mnemonic[0]),
		OpStr:    C.GoString(&ci.op_str[0]),
	}
	sz := int(ci.size)
	in.Bytes = C.GoBytes(unsafe.Pointer(&ci.bytes[0]), C.int(sz))

	// Operands via the arch-specific C helper.
	const maxOps = 16
	var cops [maxOps]C.r4_op
	cnt := int(C.r4_fill(C.int(e.arch), ci, &cops[0], C.int(maxOps)))
	if cnt > 0 {
		in.Operands = make([]Operand, cnt)
		for i := 0; i < cnt; i++ {
			c := cops[i]
			op := Operand{Type: OpType(c._type)}
			switch op.Type {
			case OpReg:
				op.Reg = uint(c.reg)
				op.RegName = e.RegName(op.Reg)
			case OpImm:
				op.Imm = int64(c.imm)
			case OpMem:
				op.Mem = Mem{
					Segment: uint(c.segment), Base: uint(c.base),
					Index: uint(c.index), Scale: int(c.scale),
					Disp: int64(c.disp),
				}
				op.Mem.SegmentName = e.RegName(op.Mem.Segment)
				op.Mem.BaseName = e.RegName(op.Mem.Base)
				op.Mem.IndexName = e.RegName(op.Mem.Index)
			}
			in.Operands[i] = op
		}
	}

	// Register access via cs_regs_access (unavailable on some arches).
	var rd, wr [64]C.uint16_t
	var nrd, nwr C.int
	if C.r4_regs(e.h, ci, &rd[0], &nrd, &wr[0], &nwr) == C.CS_ERR_OK {
		in.RegsOK = true
		in.RegsRead = make([]uint, int(nrd))
		in.RegsReadNames = make([]string, int(nrd))
		for i := 0; i < int(nrd); i++ {
			in.RegsRead[i] = uint(rd[i])
			in.RegsReadNames[i] = e.RegName(in.RegsRead[i])
		}
		in.RegsWritten = make([]uint, int(nwr))
		in.RegsWrittenNames = make([]string, int(nwr))
		for i := 0; i < int(nwr); i++ {
			in.RegsWritten[i] = uint(wr[i])
			in.RegsWrittenNames[i] = e.RegName(in.RegsWritten[i])
		}
	}
	return in
}

// Version returns the libcapstone major.minor the wrapper is linked against.
func Version() (major, minor int) {
	var a, b C.int
	C.cs_version(&a, &b)
	return int(a), int(b)
}
