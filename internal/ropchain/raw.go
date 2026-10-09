package ropchain

import (
	"fmt"
	"strings"

	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/operation"
)

// This file ports rop3 ropchain.py's raw(...) explicit-gadget parsing:
// _parse_raw_line / _parse_explicit_gadget_fields and the _raw_* helpers. A
// raw(...) line becomes a chain step carrying its own inline OperationDef, so
// the classifier/assembler consume it unchanged; the only difference is that
// its definition is built here instead of resolved from the operation catalog.

// parseRawLine parses an explicit-gadget line into a chain step carrying its own
// inline OperationDef (rop3 RopChain._parse_raw_line):
//
//	raw([mnemonic, ...], [operands], [dst], [src])
//
// A raw gadget carries no ret/branch terminator requirement: its candidates
// come from GadFinder.FindRawGadgets (a direct scan independent of the backward
// gadget-finder machinery), so a bare non-returning tail such as syscall / svc 0
// / ecall is expressible.
func parseRawLine(line string) (gadfinder.ChainStep, error) {
	instructions, name, dst, src, err := parseExplicitGadgetFields(line)
	if err != nil {
		return gadfinder.ChainStep{}, err
	}

	// operands=0: a raw gadget is matched exactly as written (no abstract
	// operands / multi-architecture realizations).
	defn := operation.NewOperationDef(name, 0, dst, src)
	links := []operation.LinkData{{Gadget: instructions}}
	defn.AddRealization(links)

	return gadfinder.ChainStep{Data: strings.TrimSpace(line), Op: name, Defn: defn}, nil
}

// parseExplicitGadgetFields parses the four bracketed fields of a raw(...) line
// (rop3 RopChain._parse_explicit_gadget_fields). Returns the per-instruction
// InsnData, the ' ; '-joined display name, and the dst/src register lists.
func parseExplicitGadgetFields(line string) ([]operation.InsnData, string, []string, []string, error) {
	body, err := rawBody(line)
	if err != nil {
		return nil, "", nil, nil, err
	}
	fields := splitTopLevel(body, ',')
	if len(fields) != 4 {
		return nil, "", nil, nil, fmt.Errorf("a raw gadget needs exactly four bracketed fields: [mnemonics], [operands], [dst], [src]")
	}

	mnemonics, err := rawList(fields[0], "mnemonics")
	if err != nil {
		return nil, "", nil, nil, err
	}
	if len(mnemonics) == 0 {
		return nil, "", nil, nil, fmt.Errorf("a raw gadget needs at least one mnemonic")
	}
	perInstrOps, err := rawOperands(fields[1], len(mnemonics))
	if err != nil {
		return nil, "", nil, nil, err
	}
	dst, err := rawList(fields[2], "dst")
	if err != nil {
		return nil, "", nil, nil, err
	}
	src, err := rawList(fields[3], "src")
	if err != nil {
		return nil, "", nil, nil, err
	}

	instructions := make([]operation.InsnData, len(mnemonics))
	nameParts := make([]string, len(mnemonics))
	for i, m := range mnemonics {
		ops := perInstrOps[i]
		anyOps := make([]any, len(ops))
		for j, o := range ops {
			anyOps[j] = o
		}
		instructions[i] = operation.InsnData{Mnemonic: m, Operands: anyOps}
		nameParts[i] = strings.TrimSpace(m + " " + strings.Join(ops, ", "))
	}
	name := strings.Join(nameParts, " ; ")

	return instructions, name, dst, src, nil
}

// rawBody returns the text between the outermost parentheses of a raw(...) line,
// with any trailing ; comment removed (rop3 _raw_body).
func rawBody(line string) (string, error) {
	line = strings.TrimSpace(stripLineComment(line))
	open := strings.Index(line, "(")
	if open == -1 || !strings.HasSuffix(line, ")") {
		return "", fmt.Errorf("malformed raw gadget: expected raw(...)")
	}
	return line[open+1 : len(line)-1], nil
}

// stripLineComment drops a trailing ; comment, ignoring any ; nested inside
// brackets (rop3 _strip_line_comment).
func stripLineComment(line string) string {
	depth := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '[', '(':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				return line[:i]
			}
		}
	}
	return line
}

// splitTopLevel splits s on sep at bracket depth 0, honouring [] and ()
// nesting, and strips each part (rop3 _split_top_level).
func splitTopLevel(s string, sep byte) []string {
	var parts []string
	depth := 0
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '[', '(':
			depth++
		case ')', ']':
			depth--
		}
		if ch == sep && depth == 0 {
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		} else {
			cur.WriteByte(ch)
		}
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts
}

// unbracket strips a [ ] wrapper from a field (rop3 _unbracket).
func unbracket(field, what string) (string, error) {
	field = strings.TrimSpace(field)
	if !(strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]")) {
		return "", fmt.Errorf("the %s field must be wrapped in [ ]", what)
	}
	return strings.TrimSpace(field[1 : len(field)-1]), nil
}

// rawList returns a bracketed, comma-separated field ([a, b, c]) as a list of
// tokens, dropping empties (rop3 _raw_list).
func rawList(field, what string) ([]string, error) {
	inner, err := unbracket(field, what)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, tok := range splitTopLevel(inner, ',') {
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out, nil
}

// rawOperands resolves the operands field into a per-instruction operand list
// (one entry per mnemonic) (rop3 _raw_operands). With no (...) groups all
// operands belong to the first instruction; with groups, each top-level element
// is one instruction's operands.
func rawOperands(field string, nInstr int) ([][]string, error) {
	inner, err := unbracket(field, "operands")
	if err != nil {
		return nil, err
	}
	var elements []string
	for _, e := range splitTopLevel(inner, ',') {
		if e != "" {
			elements = append(elements, e)
		}
	}
	perInstr := make([][]string, nInstr)
	for i := range perInstr {
		perInstr[i] = []string{}
	}
	if len(elements) == 0 {
		return perInstr, nil
	}

	grouped := false
	for _, e := range elements {
		if strings.HasPrefix(e, "(") && strings.HasSuffix(e, ")") {
			grouped = true
			break
		}
	}
	if !grouped {
		perInstr[0] = elements
		return perInstr, nil
	}

	if len(elements) > nInstr {
		return nil, fmt.Errorf("%d operand groups for %d instruction(s)", len(elements), nInstr)
	}
	for i, element := range elements {
		var ops []string
		if strings.HasPrefix(element, "(") && strings.HasSuffix(element, ")") {
			for _, o := range splitTopLevel(element[1:len(element)-1], ',') {
				if o != "" {
					ops = append(ops, o)
				}
			}
		} else {
			ops = []string{element}
		}
		if ops == nil {
			ops = []string{}
		}
		perInstr[i] = ops
	}
	return perInstr, nil
}
