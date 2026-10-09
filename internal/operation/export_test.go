package operation

import (
	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
)

// OperandEqualForTest exposes the unexported operandEqual for tests.
func OperandEqualForTest(a arch.Arch, allowRegAliases bool, op *Operand,
	decode *disasm.Insn, operand disasm.Operand) (string, any, bool, bool) {
	return operandEqual(a, allowRegAliases, op, decode, operand)
}

// ParseImmForTest exposes the unexported parseImm for tests.
func ParseImmForTest(v any) (int64, bool) { return parseImm(v) }

// SetBindingForTest binds an operand placeholder (exposes setBinding).
func (op *Operand) SetBindingForTest(name string, value any) { op.setBinding(name, value) }

// IsMem/IsImm/IsReg expose the operand kind predicates for tests.
func (op *Operand) IsMem() bool { return op.Mem }
func (op *Operand) IsImm() bool { return op.HasImm }
func (op *Operand) IsReg() bool { return op.isReg() }
