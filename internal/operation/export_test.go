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
