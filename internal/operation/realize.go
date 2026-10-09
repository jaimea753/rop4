package operation

import (
	"fmt"
	"strings"
)

// Operations are *defined* with N named operands (opN), but a ROP chain is
// *constructed* only from 2-operand primitives. Realize resolves an operation
// into a flat list of 2-operand primitive steps. It ports operation.realize and
// its helpers. The ROP-chain assembler that consumes these steps is a separate
// workstream; Realize is ported here so it is ready for it.

// Step is one 2-operand primitive step of a realized chain.
type Step struct {
	Data string
	Op   string
	Defn *OperationDef
	Op1  any
	Op2  any
}

// ResolveFunc resolves a referenced operation name to its definition during
// realization (rop3 operation._resolve_ref -> parser.Parser().get_op).
type ResolveFunc func(name string) (*OperationDef, error)

// IsPrimitive reports whether every realization of defn is a single gadget.
func IsPrimitive(defn *OperationDef) bool {
	if len(defn.Realizations) == 0 {
		return false
	}
	for _, r := range defn.Realizations {
		if !r.IsSingleGadget() {
			return false
		}
	}
	return true
}

// operandNames returns the abstract operand names appearing in a pattern, in
// order.
func operandNames(set *Set) []string {
	var names []string
	seen := map[string]bool{}
	for _, ins := range set.Items {
		for _, op := range ins.Operands {
			if op.Abstract && !seen[op.Reg] {
				seen[op.Reg] = true
				names = append(names, op.Reg)
			}
		}
	}
	return names
}

// inlineOperationDef wraps an inline raw-gadget link as a synthetic single-
// gadget operation with positional operands op1, op2, ... (rop3
// _inline_operation_def). Returns (defn, originalNames).
func inlineOperationDef(set *Set) (*OperationDef, []string) {
	names := operandNames(set)
	rename := map[string]string{}
	var positional []string
	for i, orig := range names {
		slot := fmt.Sprintf("op%d", i+1)
		rename[orig] = slot
		positional = append(positional, slot)
	}
	renamed := set.renamed(rename)
	mnemonic := "inline"
	if len(renamed.Items) > 0 {
		mnemonic = renamed.Items[0].Mnemonic
	}
	var dstRoles []string
	if len(positional) > 0 {
		dstRoles = append(dstRoles, positional[0])
	}
	dstRoles = append(dstRoles, set.ExtraWrites...)
	srcRoles := append(append([]string(nil), positional...), set.ExtraReads...)
	defn := NewOperationDef(mnemonic, len(positional), dstRoles, srcRoles)
	real := &Realization{}
	real.add(renamed)
	defn.Add(real)
	return defn, names
}

// primaryOperands returns the two operand-slot values of a primitive under
// binding: the primary destination (op1) and the primary non-accumulator
// source (op2). Unbound operands are nil.
func primaryOperands(defn *OperationDef, binding map[string]any) (any, any) {
	var op1 any
	if len(defn.DstRoles) > 0 {
		op1 = binding[defn.DstRoles[0]]
	}
	var op2 any
	dst := map[string]bool{}
	for _, r := range defn.DstRoles {
		dst[r] = true
	}
	for _, r := range defn.SrcRoles {
		if !dst[r] {
			op2 = binding[r]
			break
		}
	}
	return op1, op2
}

func formatStep(op string, op1, op2 any) string {
	inside := ""
	if op1 != nil {
		inside = toStr(op1)
	}
	if op2 != nil {
		inside += ", " + toStr(op2)
	}
	return fmt.Sprintf("%s(%s)", op, inside)
}

// Realize flattens an operation definition into its alternative realizations,
// each a flat list of 2-operand primitive steps (rop3 operation.realize).
func Realize(defn *OperationDef, binding map[string]any, resolve ResolveFunc) ([][]Step, error) {
	op := defn.Name

	if IsPrimitive(defn) {
		op1, op2 := primaryOperands(defn, binding)
		step := Step{Data: formatStep(op, op1, op2), Op: op, Defn: defn, Op1: op1, Op2: op2}
		return [][]Step{{step}}, nil
	}

	var chains [][]Step
	for _, real := range defn.Realizations {
		// Each link contributes a list of alternative sub-chains; the cartesian
		// product over the links yields this realization's chains.
		var linkAlternatives [][][]Step
		for _, link := range real.Links {
			switch l := link.(type) {
			case *OpRef:
				subBinding := map[string]any{}
				for slot, expr := range l.Bindings {
					if v, ok := binding[expr]; ok {
						subBinding[slot] = v
					} else {
						subBinding[slot] = expr
					}
				}
				sub, err := resolve(l.Name)
				if err != nil {
					return nil, err
				}
				alt, err := Realize(sub, subBinding, resolve)
				if err != nil {
					return nil, err
				}
				linkAlternatives = append(linkAlternatives, alt)
			default: // inline Set
				set := link.(*Set)
				syn, names := inlineOperationDef(set)
				values := make([]any, len(names))
				for i, name := range names {
					if v, ok := binding[name]; ok {
						values[i] = v
					} else {
						values[i] = name
					}
				}
				var op1, op2 any
				if len(values) > 0 {
					op1 = values[0]
				}
				if len(values) > 1 {
					op2 = values[1]
				}
				inlineStep := Step{Data: formatStep(syn.Name, op1, op2), Op: syn.Name,
					Defn: syn, Op1: op1, Op2: op2}
				linkAlternatives = append(linkAlternatives, [][]Step{{inlineStep}})
			}
		}
		dropped := false
		for _, alt := range linkAlternatives {
			if len(alt) == 0 {
				dropped = true
				break
			}
		}
		if dropped {
			continue // some link cannot be realized on this architecture
		}
		for _, combo := range cartesian(linkAlternatives) {
			var chain []Step
			for _, part := range combo {
				chain = append(chain, part...)
			}
			chains = append(chains, chain)
		}
	}
	return chains, nil
}

// cartesian returns the cartesian product over per-link alternative lists.
func cartesian(groups [][][]Step) [][][]Step {
	result := [][][]Step{{}}
	for _, group := range groups {
		var next [][][]Step
		for _, prefix := range result {
			for _, item := range group {
				combo := append(append([][]Step(nil), prefix...), item)
				next = append(next, combo)
			}
		}
		result = next
	}
	return result
}

// describeChain renders a chain's step data (for traces/tests).
func describeChain(chain []Step) string {
	parts := make([]string, len(chain))
	for i, s := range chain {
		parts[i] = s.Data
	}
	return strings.Join(parts, " ; ")
}

var _ = describeChain
