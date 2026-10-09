package gadfinder

import (
	"errors"
	"strings"

	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/operation"
	"github.com/reverseame/rop4/internal/roplang"
)

// ErrCompoundUnsupported is returned by FindOp when the requested operation can
// only be realized as a multi-step ROP chain (it contains operation references
// or more than one gadget). The backtracking chain assembler that turns such a
// realization into a ROP chain is a separate workstream and is not implemented
// yet; see the TODO in FindOp.
var ErrCompoundUnsupported = errors.New(
	"operation requires multi-step ROP-chain expansion, which is not yet implemented")

// parser lazily builds the ROPLang parser for the detected architecture.
func (gf *GadFinder) parser() (*roplang.Parser, error) {
	if gf.rlParser == nil {
		p, err := roplang.New(gf.arch)
		if err != nil {
			return nil, err
		}
		gf.rlParser = p
	}
	return gf.rlParser, nil
}

// FindOp resolves `op` against the ROPLang catalog and returns the gadgets that
// realize it with the given positional operands. It mirrors rop3
// GadFinder.find_op_from_gadgets.
//
// A primitive operation (every realization is a single gadget) is matched
// directly against `gadgets`. An operation that can only be realized as a
// multi-step chain returns ErrCompoundUnsupported (see that var).
func (gf *GadFinder) FindOp(gadgets []*gadget.Gadget, op string, operands []string) ([]*gadget.Gadget, error) {
	if gf.arch == nil {
		return nil, errors.New("FindOp: no architecture (scan a binary first)")
	}
	p, err := gf.parser()
	if err != nil {
		return nil, err
	}
	resolved, err := p.GetOp(op)
	if err != nil {
		return nil, err
	}

	// Operations realized as multi-step chains (containing operation refs or
	// more than one gadget) expand into ROP chains.
	hasChain := false
	for _, real := range resolved.Realizations {
		if !real.IsSingleGadget() {
			hasChain = true
			break
		}
	}
	if hasChain {
		// TODO(ropchain): expand via operation.Realize + a backtracking chain
		// assembler (rop3 RopChain.search). That assembler is a separate
		// workstream; until it lands, compound/multi-step operations are not
		// searchable through --op.
		return nil, ErrCompoundUnsupported
	}

	// Primitive branch: apply the same operand normalization the chain path
	// does -- the REG_SP/REG_BP aliases and the generic-slot/TMP_REG ->
	// "any register" mapping -- so `--op`/`--operands` behaves like a
	// single-step .ropchain file.
	resolvedOperands := make([]any, len(operands))
	for i, o := range operands {
		resolvedOperands[i] = gf.resolveOperand(o)
	}
	return operation.MatchGadgets(gf.arch, gf.has(AllowRegAliases), resolved,
		resolvedOperands, gadgets, !gf.has(KeepContradictory))
}

// resolveOperand maps a primitive operand to a match value: REG_SP/REG_BP -> the
// arch pointer register, a generic REGn slot or a TMP_REG scratch temporary ->
// nil (matches any register), anything else -> itself. Ports
// GadFinder._resolve_operand.
func (gf *GadFinder) resolveOperand(val string) any {
	if val == "" {
		return nil
	}
	if aliased := gf.resolveRegAlias(val); aliased != val {
		return aliased
	}
	if strings.HasPrefix(strings.ToLower(val), "reg") ||
		strings.HasPrefix(strings.ToUpper(val), "TMP_REG") {
		return nil
	}
	return val
}

// resolveRegAlias maps the ROPLang stack/base-pointer aliases (REG_SP/REG_BP) to
// the architecture's concrete pointer registers (rop3 resolve_reg_alias).
func (gf *GadFinder) resolveRegAlias(name string) string {
	switch name {
	case "REG_SP":
		return gf.arch.SP()
	case "REG_BP":
		return gf.arch.BP()
	default:
		return name
	}
}
