// Package output renders gadgets and ROP chains as text, json, csv, or tuple
// (ported from rop3/utils.py output_gadgets / output_ropchains).
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/reverseame/rop4/internal/gadget"
)

const Version = "2.0.0"

// gadgetJSON matches rop3 Gadget.to_dict's field order. A nil slice marshals to
// JSON null (rop3 emits null for empty dst/src and absent bytes/symbol/op);
// Modifies is always a (possibly empty) array.
type gadgetJSON struct {
	File         string   `json:"file"`
	Vaddr        string   `json:"vaddr"`
	Gadget       string   `json:"gadget"`
	Instructions []string `json:"instructions"`
	Bytes        *string  `json:"bytes"`
	Count        *int     `json:"count"`
	Symbol       *string  `json:"symbol"`
	Op           *string  `json:"op"`
	Dst          []string `json:"dst"`
	Src          []string `json:"src"`
	Modifies     []string `json:"modifies"`
}

func toJSON(g *gadget.Gadget) gadgetJSON {
	d := g.ToDict()
	j := gadgetJSON{
		File:         d["file"].(string),
		Vaddr:        d["vaddr"].(string),
		Gadget:       d["gadget"].(string),
		Instructions: d["instructions"].([]string),
		Modifies:     ensureSlice(d["modifies"]),
	}
	if c := d["count"].(int); c != 0 {
		j.Count = &c
	}
	if b, ok := d["bytes"].(string); ok {
		j.Bytes = &b
	}
	if s, ok := d["symbol"].(string); ok {
		j.Symbol = &s
	}
	if o, ok := d["op"].(string); ok {
		j.Op = &o
	}
	if v, ok := d["dst"].([]string); ok {
		j.Dst = v
	}
	if v, ok := d["src"].([]string); ok {
		j.Src = v
	}
	return j
}

func ensureSlice(v any) []string {
	if s, ok := v.([]string); ok && s != nil {
		return s
	}
	return []string{}
}

func gadgetTupleLine(g *gadget.Gadget) string {
	return fmt.Sprintf("[%s @ %#x]: %s", baseName(g.Filename), g.Vaddr, g.TupleRepr())
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// Gadgets writes a flat gadget list to w in the given format.
func Gadgets(w io.Writer, gadgets []*gadget.Gadget, format string) error {
	switch format {
	case "json":
		arr := make([]gadgetJSON, len(gadgets))
		for i, g := range gadgets {
			arr[i] = toJSON(g)
		}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(arr)
	case "csv":
		cw := csv.NewWriter(w)
		cw.UseCRLF = true
		cols := []string{"file", "vaddr", "gadget", "bytes", "count", "symbol", "op", "dst", "src", "modifies"}
		cw.Write(cols)
		for _, g := range gadgets {
			cw.Write(csvRecord(g, cols))
		}
		cw.Flush()
		return cw.Error()
	case "tuple":
		for _, g := range gadgets {
			fmt.Fprintln(w, gadgetTupleLine(g))
		}
	default: // text
		for _, g := range gadgets {
			fmt.Fprintln(w, g.String())
		}
	}
	return nil
}

// pyListRepr renders a string slice as a Python list literal, matching how
// rop3's csv.DictWriter stringifies the dst/src list fields (e.g. ['rax', 'rbx']).
func pyListRepr(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = "'" + x + "'"
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func csvRecord(g *gadget.Gadget, cols []string) []string {
	d := g.ToDict()
	row := make([]string, len(cols))
	for i, c := range cols {
		switch c {
		case "modifies":
			row[i] = strings.Join(ensureSlice(d["modifies"]), " ")
		case "count":
			if c := d["count"].(int); c != 0 {
				row[i] = fmt.Sprintf("%d", c)
			}
		case "dst", "src":
			// rop3's csv.DictWriter stringifies the Python list, e.g. ['rdi'].
			if v, ok := d[c].([]string); ok {
				row[i] = pyListRepr(v)
			}
		default:
			if s, ok := d[c].(string); ok {
				row[i] = s
			}
		}
	}
	return row
}

// printRopchain prints one chain; when idx>0 it is wrapped with a header and a
// trailing blank line (rop3 print_ropchain).
func printRopchain(w io.Writer, chain []*gadget.Gadget, idx int, format string) {
	if idx > 0 {
		fmt.Fprintf(w, "%s Ropchain %d %s\n", strings.Repeat("#", 40), idx, strings.Repeat("#", 40))
	}
	for _, g := range chain {
		if format == "tuple" {
			fmt.Fprintln(w, gadgetTupleLine(g))
		} else {
			fmt.Fprintln(w, g.String())
		}
	}
	if idx > 0 {
		fmt.Fprintln(w)
	}
}

// Ropchains writes ROP chains (each a gadget list) in the given format
// (rop3 output_ropchains). For text/tuple without exhaustive, only the first
// chain is printed (unheadered).
func Ropchains(w io.Writer, chains [][]*gadget.Gadget, format string, exhaustive bool) error {
	if (format == "text" || format == "tuple") && !exhaustive {
		if len(chains) > 0 {
			printRopchain(w, chains[0], 0, format)
		}
		return nil
	}
	switch format {
	case "json":
		arr := make([][]gadgetJSON, len(chains))
		for i, chain := range chains {
			row := make([]gadgetJSON, len(chain))
			for j, g := range chain {
				row[j] = toJSON(g)
			}
			arr[i] = row
		}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(arr)
	case "csv":
		cw := csv.NewWriter(w)
		cw.UseCRLF = true
		cols := []string{"file", "vaddr", "gadget", "bytes", "count", "symbol", "op", "dst", "src", "modifies"}
		cw.Write(append([]string{"chain"}, cols...))
		for idx, chain := range chains {
			for _, g := range chain {
				cw.Write(append([]string{fmt.Sprintf("%d", idx+1)}, csvRecord(g, cols)...))
			}
		}
		cw.Flush()
		return cw.Error()
	default: // text or tuple
		for idx, chain := range chains {
			printRopchain(w, chain, idx+1, format)
		}
	}
	return nil
}
