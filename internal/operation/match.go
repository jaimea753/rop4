package operation

import (
	"fmt"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadget"
)

// OperationNotAvailableError reports an operation explicitly marked unavailable
// for the current architecture (rop3 parser.OperationNotAvailable).
type OperationNotAvailableError struct {
	Name   string
	Reason string
}

func (e *OperationNotAvailableError) Error() string {
	reason := e.Reason
	if reason == "" {
		reason = "not available for this architecture"
	}
	return fmt.Sprintf("%s: %s", e.Name, reason)
}

// matchResult pairs a (bindings, indices) match.
type matchResult struct {
	binds   map[string]any
	indices []int
}

// MatchGadgets returns copies of the gadgets whose instructions realize `defn`
// with the given positional operands. A nil entry in operands leaves that
// operand unconstrained. Ports operation.match_gadgets.
//
// `a` and `allowRegAliases` replace rop3's arch_singleton / allow_reg_aliases.
func MatchGadgets(a arch.Arch, allowRegAliases bool, defn *OperationDef,
	operands []any, gadgets []*gadget.Gadget, rejectClobbered bool) ([]*gadget.Gadget, error) {
	if !defn.Available {
		return nil, &OperationNotAvailableError{Name: defn.Name, Reason: defn.UnavailableReason}
	}

	bindings := operandBindings(operands)
	var ret []*gadget.Gadget
	if len(gadgets) == 0 {
		return ret, nil
	}

	// The values the operation's destination roles bind to (an unbound dst role
	// keeps its opN name), used to refuse the reg->imm substitution on a dst.
	dstValues := map[string]bool{}
	for _, r := range defn.DstRoles {
		if v, ok := bindings[r]; ok {
			dstValues[toStr(v)] = true
		} else {
			dstValues[r] = true
		}
	}

	for _, real := range defn.Realizations {
		if !real.IsSingleGadget() {
			continue
		}
		set := real.Links[0].(*Set).bound(bindings)
		markDstOperands(set, dstValues)
		for _, g := range gadgets {
			for _, m := range allMatches(a, allowRegAliases, set, g.Decodes, g.Frame) {
				if rejectClobbered && g.ResultClobbered(m.indices,
					destinationRegisters(a, defn, bindings, m.binds)) {
					continue
				}
				ret = append(ret, annotate(a, defn, bindings, g, m.binds))
			}
		}
	}
	return ret, nil
}

// operandBindings maps positional operands to op1/op2/... slots, dropping nil
// (unconstrained) operands.
func operandBindings(operands []any) map[string]any {
	bindings := map[string]any{}
	for i, value := range operands {
		if value != nil {
			bindings[fmt.Sprintf("op%d", i+1)] = value
		}
	}
	return bindings
}

// asRegister returns the concrete register bound to an operand name (following
// one level of placeholder indirection), or ("", false) when it is an immediate
// or unbound.
func asRegister(a arch.Arch, bindings map[string]any, name string, binds map[string]any) (string, bool) {
	var val any = name
	if v, ok := bindings[name]; ok {
		val = v
	}
	if s, ok := val.(string); ok && IsAbstractName(s) {
		if v, ok := binds[s]; ok {
			val = v
		}
	}
	s, ok := val.(string)
	if !ok || IsAbstractName(s) || isImmediate(val) {
		return "", false
	}
	return a.NormalizeReg(s), true
}

// asOperand returns the display value bound to an operand name: a concrete
// register or a formatted immediate, or ("", false) when still unbound/unused.
func asOperand(a arch.Arch, bindings map[string]any, name string, binds map[string]any) (string, bool) {
	var val any = name
	if v, ok := bindings[name]; ok {
		val = v
	}
	if s, ok := val.(string); ok && IsAbstractName(s) {
		if v, ok := binds[s]; ok {
			val = v
		}
	}
	if s, ok := val.(string); ok && IsAbstractName(s) {
		return "", false // still an unbound placeholder
	}
	if isImmediate(val) {
		return formatImm(val), true
	}
	if s, ok := val.(string); ok {
		return a.NormalizeReg(s), true
	}
	return "", false
}

// destinationRegisters returns the concrete destination register(s) the
// operation writes, for the contradictory-gadget guard.
func destinationRegisters(a arch.Arch, defn *OperationDef, bindings, binds map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, n := range defn.DstRoles {
		if r, ok := asRegister(a, bindings, n, binds); ok {
			out[r] = true
		}
	}
	return out
}

// markDstOperands flags each operand of the (bound) pattern that sits in a
// destination role, so operandEqual refuses the reg->imm substitution for it.
func markDstOperands(set *Set, dstValues map[string]bool) {
	for _, item := range set.Items {
		for _, operand := range item.Operands {
			operand.IsDstRole = dstValues[operand.Reg]
		}
	}
}

// annotate returns an annotated copy so the shared input gadget is not mutated.
func annotate(a arch.Arch, defn *OperationDef, bindings map[string]any,
	g *gadget.Gadget, binds map[string]any) *gadget.Gadget {
	matched := *g
	matched.Op = defn.Name
	matched.Dst = map[string]bool{}
	matched.Src = map[string]bool{}
	matched.SideRegs = map[string]bool{}
	for _, n := range defn.DstRoles {
		if r, ok := asRegister(a, bindings, n, binds); ok {
			matched.Dst[r] = true
		}
	}
	for _, n := range defn.SrcRoles {
		if r, ok := asRegister(a, bindings, n, binds); ok {
			matched.Src[r] = true
		}
	}
	slot1, _ := asRegister(a, bindings, "op1", binds)
	slot2, _ := asRegister(a, bindings, "op2", binds)
	if disp1, ok := asOperand(a, bindings, "op1", binds); ok {
		matched.SetSlotOp1(slot1, disp1)
	}
	if disp2, ok := asOperand(a, bindings, "op2", binds); ok {
		matched.SetSlotOp2(slot2, disp2)
	}
	matched.CalculateSideEffects()
	return &matched
}

// --- Set matching (iter_matches / _match_run) -----------------------------

// allMatches returns every (bindings, indices) at which the pattern matches.
func allMatches(a arch.Arch, allowRegAliases bool, s *Set, decodes []*disasm.Insn, frame []bool) []matchResult {
	var out []matchResult
	if len(s.Items) == 0 {
		out = append(out, matchResult{binds: map[string]any{}, indices: nil})
		return out
	}

	n := len(decodes)
	k := len(s.Items)
	if n < k {
		return nil
	}

	if frame == nil {
		// Derive the same mask the scans build inline: the terminator plus any
		// stacked return-address restore.
		frame = make([]bool, n)
		last := n - 1
		for i, insn := range decodes {
			frame[i] = i == last || a.RestoresReturnAddress(insn)
		}
	}

	noPreFrameJunk := frame[0]
	enteredFrame := false
	for anchor := 0; anchor <= n-k; anchor++ {
		if !frame[anchor] && (anchor == 0 || (enteredFrame && noPreFrameJunk)) {
			last := n - 1
			swallowsPrologue := false
			for i := anchor + 1; i < anchor+k; i++ {
				if frame[i] && i != last {
					swallowsPrologue = true
					break
				}
			}
			if !swallowsPrologue {
				if binds, indices, ok := matchRun(a, allowRegAliases, s, decodes, anchor); ok {
					out = append(out, matchResult{binds: binds, indices: indices})
				}
			}
		}
		if frame[anchor] {
			enteredFrame = true
		}
	}
	return out
}

// matchRun matches the pattern as a consecutive run anchored at start.
func matchRun(a arch.Arch, allowRegAliases bool, s *Set, decodes []*disasm.Insn, start int) (map[string]any, []int, bool) {
	bindings := map[string]any{}
	var indices []int
	for offset, item := range s.Items {
		binds, ok := instructionEqual(a, allowRegAliases, item, decodes[start+offset])
		if !ok {
			return nil, nil, false
		}
		for name, val := range binds {
			if existing, ok := bindings[name]; ok && existing != val {
				return nil, nil, false
			}
			bindings[name] = val
		}
		indices = append(indices, start+offset)
	}
	return bindings, indices, true
}

// instructionEqual ports Instruction.is_equal.
func instructionEqual(a arch.Arch, allowRegAliases bool, ins *Instruction, decode *disasm.Insn) (map[string]any, bool) {
	if ins.Mnemonic != decode.Mnemonic {
		return nil, false
	}
	if len(ins.Operands) != len(decode.Operands) {
		return nil, false
	}
	bindings := map[string]any{}
	for i, myOperand := range ins.Operands {
		name, val, hasBind, ok := operandEqual(a, allowRegAliases, myOperand, decode, decode.Operands[i])
		if !ok {
			return nil, false
		}
		if hasBind {
			if existing, ok := bindings[name]; ok && existing != val {
				return nil, false
			}
			bindings[name] = val
		}
	}
	return bindings, true
}

// operandEqual ports Operand.is_equal. It returns (bindName, bindVal, hasBind,
// matched). Operand register names are pre-resolved by the disasm layer
// (.RegName / .Mem.BaseName).
func operandEqual(a arch.Arch, allowRegAliases bool, op *Operand,
	decode *disasm.Insn, operand disasm.Operand) (string, any, bool, bool) {
	// A wildcard matches any operand and binds nothing.
	if op.Wildcard {
		return "", nil, false, true
	}

	// A generic register operand may match an immediate (reg -> imm subst), but
	// never a memory operand and never a destination operand.
	if op.Abstract && op.isReg() && !op.IsDstRole && operand.Type == disasm.OpImm {
		return op.Reg, operand.Imm, true, true
	}

	if op.Mem {
		if operand.Type != disasm.OpMem {
			return "", nil, false, false
		}
		base := operand.Mem.BaseName
		if op.Abstract {
			if !aliasOK(a, allowRegAliases, base) {
				return "", nil, false, false
			}
			return op.Reg, a.NormalizeReg(base), true, true
		}
		return "", nil, false, a.ConcreteRegEqual(base, op.Reg)
	}

	if op.HasImm {
		if operand.Type != disasm.OpImm {
			return "", nil, false, false
		}
		return "", nil, false, operand.Imm == op.Imm
	}

	// register operand
	if operand.Type != disasm.OpReg {
		return "", nil, false, false
	}
	reg := operand.RegName
	if op.Abstract {
		if !aliasOK(a, allowRegAliases, reg) {
			return "", nil, false, false
		}
		return op.Reg, a.NormalizeReg(reg), true, true
	}
	return "", nil, false, a.ConcreteRegEqual(reg, op.Reg)
}

// aliasOK reports whether a concrete register may fill an abstract operand.
func aliasOK(a arch.Arch, allowRegAliases bool, reg string) bool {
	return allowRegAliases || a.IsValidAbstractReg(reg)
}
