// Package roplang ports rop3/rop3/parser.py and rop3/rop3/parsers/yaml_parser.py:
// it loads the embedded ROPLang operation catalog (YAML) into
// operation.OperationDef values for the current architecture.
//
// rop3 loaded the catalog from disk via a recursive glob and read the global
// arch_singleton. rop4 embeds the catalog into the binary (so it is
// self-contained) and threads an explicit arch.Arch.
package roplang

import (
	"fmt"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/operation"
)

// ParserError reports a catalog lookup/parse failure (rop3 parser.ParserException).
type ParserError struct{ Msg string }

func (e *ParserError) Error() string { return e.Msg }

// Parser resolves ROPLang operation names to OperationDefs for one architecture.
type Parser struct {
	a    arch.Arch
	ops  []*operation.OperationDef
	byID map[string]*operation.OperationDef
}

// New builds a parser bound to arch `a`, loading and parsing the embedded
// catalog once.
func New(a arch.Arch) (*Parser, error) {
	p := &Parser{a: a, byID: map[string]*operation.OperationDef{}}
	ops, err := p.loadOps()
	if err != nil {
		return nil, err
	}
	p.ops = ops
	for _, op := range ops {
		p.byID[op.Name] = op
	}
	return p, nil
}

// GetOp returns the named operation's definition.
func (p *Parser) GetOp(op string) (*operation.OperationDef, error) {
	if defn, ok := p.byID[op]; ok {
		return defn, nil
	}
	return nil, &ParserError{Msg: fmt.Sprintf("%s: Operation not found", op)}
}

// GetOps returns every operation definition in the catalog.
func (p *Parser) GetOps() []*operation.OperationDef { return p.ops }

// Resolve returns an operation.ResolveFunc backed by this parser (for
// operation.Realize's opref resolution).
func (p *Parser) Resolve() operation.ResolveFunc {
	return func(name string) (*operation.OperationDef, error) {
		defn, err := p.GetOp(name)
		if err != nil {
			return nil, &ParserError{Msg: fmt.Sprintf("%s: undefined operation referenced", name)}
		}
		return defn, nil
	}
}

// archFamily returns the YAML architecture block key for the current arch.
func (p *Parser) archFamily() string {
	switch p.a.CSArch() {
	case disasm.ArchX86:
		return "x86"
	case disasm.ArchARM64:
		return "arm"
	case disasm.ArchRISCV:
		return "riscv"
	default:
		return "x86"
	}
}

// resolveAlias maps the arch-independent register aliases to concrete registers.
func (p *Parser) resolveAlias(value any) any {
	s, ok := value.(string)
	if !ok {
		return value
	}
	switch s {
	case "REG_SP":
		return p.a.SP()
	case "REG_BP":
		return p.a.BP()
	case "REG_FLAGS":
		return p.a.Flags()
	default:
		return value
	}
}

// resolveRoles resolves a dst/src role list, mapping register aliases to
// concrete names while leaving operand slots and TMP_REG temporaries untouched.
func (p *Parser) resolveRoles(roles []string) []string {
	if len(roles) == 0 {
		return nil
	}
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i], _ = p.resolveAlias(r).(string)
	}
	return out
}
