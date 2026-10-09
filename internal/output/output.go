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
			if v, ok := d[c].([]string); ok {
				row[i] = strings.Join(v, " ")
			}
		default:
			if s, ok := d[c].(string); ok {
				row[i] = s
			}
		}
	}
	return row
}
