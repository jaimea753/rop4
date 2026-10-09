// Package operation ports rop3/rop3/operation.py: the ROPLang operation data
// model (OperationDef / Realization / Set / OpRef / Instruction / Operand), the
// operation matcher (match.go) and the compound-realization expander
// (realize.go).
//
// rop3 read the process-global arch_singleton (its arch and its
// allow_reg_aliases flag) from inside the matcher. rop4 has no global: the
// matcher functions take an explicit (a arch.Arch, allowRegAliases bool) pair,
// threaded by the finder.
package operation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Abstract operand placeholders: operation operands op1, op2, op3, ..., generic
// register slots REG1, REG10, ..., and TMP_REG scratch temporaries (TMP_REG,
// TMP_REG1, ...) that an operation drops once it ends.
var abstractRE = regexp.MustCompile(`^(op\d+|REG\d+|TMP_REG\d*)$`)

// IsAbstractName reports whether name is an abstract operand placeholder.
func IsAbstractName(name string) bool { return abstractRE.MatchString(name) }

// isImmediate reports whether v is a numeric immediate (e.g. 8, "8", "0x10",
// "#0", -1) rather than a register name.
func isImmediate(v any) bool {
	_, ok := parseImm(v)
	return ok
}

// parseImm parses an immediate (int or string, optionally "#"-prefixed, base 0),
// mirroring rop3 is_immediate / _parse_imm.
func parseImm(v any) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false
	case int:
		return int64(x), true
	case int64:
		return x, true
	case string:
		s := strings.TrimPrefix(x, "#")
		n, err := strconv.ParseInt(s, 0, 64)
		if err != nil {
			// Also accept unsigned-range hex literals that overflow int64.
			if u, uerr := strconv.ParseUint(s, 0, 64); uerr == nil {
				return int64(u), true
			}
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// toStr renders a binding value (string or int) as a string.
func toStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return fmt.Sprint(x)
	}
}

// formatImm renders an immediate the way the disassembly does: small magnitudes
// in decimal, larger ones in hex (rop3 _format_imm).
func formatImm(v any) string {
	n, _ := parseImm(v)
	if n > -256 && n < 256 {
		return strconv.FormatInt(n, 10)
	}
	if n < 0 {
		return "-0x" + strconv.FormatInt(-n, 16)
	}
	return "0x" + strconv.FormatInt(n, 16)
}

// wildcard is the pattern token for a wildcard operand.
const wildcard = "ANY"

// Operand is a pattern operand: a register (abstract placeholder like op1/REG1,
// or a concrete reg name), a memory reference [base] (abstract or concrete
// base), or an immediate.
type Operand struct {
	Mem      bool
	Abstract bool
	Wildcard bool
	Reg      string
	Imm      int64
	HasImm   bool
	// IsDstRole marks an operand that sits in a destination role of its
	// operation (set by markDstOperands after binding). A destination may never
	// bind to an immediate, so the reg->imm substitution is refused for it.
	IsDstRole bool
}

// NewOperand parses a YAML operand value (string, int, or nil) into an Operand.
func NewOperand(value any) *Operand {
	op := &Operand{}
	op.parse(value)
	return op
}

func (op *Operand) parse(value any) {
	if value == nil {
		op.Wildcard = true
		return
	}
	s := toStr(value)
	if s == wildcard {
		op.Wildcard = true
		return
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		op.Mem = true
		s = s[1 : len(s)-1]
	}
	if !op.Mem {
		if imm, ok := parseImm(s); ok {
			op.Imm = imm
			op.HasImm = true
			return
		}
	}
	op.Reg = s
	op.Abstract = IsAbstractName(s)
}

func (op *Operand) isReg() bool { return !op.Mem && !op.Wildcard && !op.HasImm }

func (op *Operand) clone() *Operand {
	c := *op
	return &c
}

func (op *Operand) String() string {
	if op.Wildcard {
		return wildcard
	}
	if op.Mem {
		return "[" + op.Reg + "]"
	}
	if op.HasImm {
		return strconv.FormatInt(op.Imm, 10)
	}
	return op.Reg
}

// setBinding binds this operand if it is the abstract placeholder `name`.
// Binding to another placeholder keeps the operand abstract.
func (op *Operand) setBinding(name string, value any) {
	if !op.Abstract || op.Reg != name {
		return
	}
	if !op.Mem {
		if imm, ok := parseImm(value); ok {
			op.Imm = imm
			op.HasImm = true
			op.Reg = ""
			op.Abstract = false
			return
		}
	}
	s := toStr(value)
	op.Reg = s
	op.Abstract = IsAbstractName(s)
}

// Instruction is a pattern instruction: a mnemonic plus ordered operands.
type Instruction struct {
	Mnemonic string
	Operands []*Operand
}

func (ins *Instruction) add(op *Operand) { ins.Operands = append(ins.Operands, op) }

func (ins *Instruction) clone() *Instruction {
	c := &Instruction{Mnemonic: ins.Mnemonic}
	for _, op := range ins.Operands {
		c.Operands = append(c.Operands, op.clone())
	}
	return c
}

func (ins *Instruction) String() string {
	parts := make([]string, len(ins.Operands))
	for i, op := range ins.Operands {
		parts[i] = op.String()
	}
	return ins.Mnemonic + " " + strings.Join(parts, ", ")
}

// Link is a realization link: either a Set (a gadget-pattern) or an OpRef.
type Link interface{ isLink() }

func (*Set) isLink()   {}
func (*OpRef) isLink() {}

// Set is a gadget-pattern: consecutive instructions matched within one gadget.
type Set struct {
	Items       []*Instruction
	ExtraWrites []string
	ExtraReads  []string
}

func (s *Set) add(ins *Instruction) { s.Items = append(s.Items, ins) }

func (s *Set) String() string {
	parts := make([]string, len(s.Items))
	for i, ins := range s.Items {
		parts[i] = ins.String()
	}
	return strings.Join(parts, " ; ")
}

func (s *Set) clone() *Set {
	c := &Set{
		ExtraWrites: append([]string(nil), s.ExtraWrites...),
		ExtraReads:  append([]string(nil), s.ExtraReads...),
	}
	for _, ins := range s.Items {
		c.Items = append(c.Items, ins.clone())
	}
	return c
}

// bound returns a copy with the given operand names bound to concrete values.
// Each operand is bound once by its own name, so binding cannot cascade.
func (s *Set) bound(bindings map[string]any) *Set {
	clone := s.clone()
	for _, item := range clone.Items {
		for _, operand := range item.Operands {
			name := operand.Reg
			if operand.Abstract {
				if v, ok := bindings[name]; ok {
					operand.setBinding(name, v)
				}
			}
		}
	}
	return clone
}

// renamed returns a copy with abstract operand names remapped.
func (s *Set) renamed(mapping map[string]string) *Set {
	clone := s.clone()
	for _, item := range clone.Items {
		for _, operand := range item.Operands {
			if operand.Abstract {
				if v, ok := mapping[operand.Reg]; ok {
					operand.Reg = v
				}
			}
		}
	}
	return clone
}

// OpRef is a step that reuses another operation, binding its operands.
type OpRef struct {
	Name     string
	Bindings map[string]string // sub-op operand -> outer operand/value
}

// Realization is one alternative realization: an ordered chain of links.
type Realization struct {
	Links []Link
}

func (r *Realization) add(link Link) { r.Links = append(r.Links, link) }

// IsSingleGadget reports whether this realization is a single gadget-pattern.
func (r *Realization) IsSingleGadget() bool {
	if len(r.Links) != 1 {
		return false
	}
	_, ok := r.Links[0].(*Set)
	return ok
}

// OperationDef is the parsed definition of a ROPLang operation for the current
// architecture.
type OperationDef struct {
	Name              string
	Operands          int
	DstRoles          []string
	SrcRoles          []string
	Realizations      []*Realization
	Available         bool
	UnavailableReason string
}

// NewOperationDef builds an OperationDef (available by default).
func NewOperationDef(name string, operands int, dstRoles, srcRoles []string) *OperationDef {
	return &OperationDef{
		Name:      name,
		Operands:  operands,
		DstRoles:  append([]string(nil), dstRoles...),
		SrcRoles:  append([]string(nil), srcRoles...),
		Available: true,
	}
}

// Add appends a built realization.
func (d *OperationDef) Add(r *Realization) { d.Realizations = append(d.Realizations, r) }

// MarkUnavailable flags this operation as not realizable on the current arch.
func (d *OperationDef) MarkUnavailable(reason string) {
	d.Available = false
	d.UnavailableReason = reason
}

// LinkData is neutral link data consumed by AddRealization (built by the parser
// so it never touches the internal node types directly).
type LinkData struct {
	// Gadget instructions of one gadget-pattern link (nil for an OpRef link).
	Gadget []InsnData
	Writes []string
	Reads  []string
	// OpRef link.
	OpRef    string
	Bindings map[string]string
}

// InsnData is one instruction as neutral data.
type InsnData struct {
	Mnemonic string
	Operands []any
}

// AddRealization appends a realization built from neutral link data.
func (d *OperationDef) AddRealization(links []LinkData) {
	real := &Realization{}
	for _, link := range links {
		if link.OpRef != "" {
			b := map[string]string{}
			for k, v := range link.Bindings {
				b[k] = v
			}
			real.add(&OpRef{Name: link.OpRef, Bindings: b})
			continue
		}
		s := &Set{}
		for _, insn := range link.Gadget {
			ins := &Instruction{Mnemonic: insn.Mnemonic}
			for _, operand := range insn.Operands {
				ins.add(NewOperand(operand))
			}
			s.add(ins)
		}
		s.ExtraWrites = append([]string(nil), link.Writes...)
		s.ExtraReads = append([]string(nil), link.Reads...)
		real.add(s)
	}
	d.Realizations = append(d.Realizations, real)
}
