// Package gadget defines the Gadget value type (ported from rop3/gadget.py).
package gadget

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
)

const (
	warningColor = "\033[93m"
	frameColor   = "\033[90m"
	endColor     = "\033[0m"
)

func colorize(text, color string) string {
	if colorEnabled() {
		return color + text + endColor
	}
	return text
}

func colorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Gadget is a discovered gadget. It is compared and hashed by TextRepr only
// (see Key); the Arch back-reference and annotations never affect identity.
type Gadget struct {
	Filename string
	Arch     arch.Arch
	Vaddr    uint64
	Decodes  []*disasm.Insn
	TextRepr string
	Bytes    []byte
	Count    int
	Op       string
	Dst      map[string]bool // concrete registers written (operand slots)
	Src      map[string]bool // concrete registers read
	Symbol   string
	// Frame is a per-instruction framing mask parallel to Decodes (nil when
	// unknown, which falls back to plain anchoring).
	Frame []bool

	SideRegs map[string]bool
	SlotOp1  string
	SlotOp2  string
	DispOp1  string
	DispOp2  string
	hasOp1   bool
	hasOp2   bool
}

// New builds a Gadget and computes its text representation.
func New(filename string, a arch.Arch, vaddr uint64, decodes []*disasm.Insn, b []byte, frame []bool) *Gadget {
	g := &Gadget{
		Filename: filename, Arch: a, Vaddr: vaddr, Decodes: decodes,
		Bytes: b, Frame: frame, SideRegs: map[string]bool{},
	}
	g.TextRepr = insnsText(decodes)
	return g
}

func insnText(d *disasm.Insn) string {
	if d.OpStr != "" {
		return d.Mnemonic + " " + d.OpStr
	}
	return d.Mnemonic
}

func insnsText(decodes []*disasm.Insn) string {
	parts := make([]string, len(decodes))
	for i, d := range decodes {
		parts[i] = insnText(d)
	}
	return strings.Join(parts, " ; ")
}

// Key is the dedup/equality key (rop3 Gadget.__eq__/__hash__ over text_repr).
func (g *Gadget) Key() string { return g.TextRepr }

// CalculateSideEffects fills SideRegs with written registers other than sp and
// the operation's own destinations.
func (g *Gadget) CalculateSideEffects() {
	a := g.Arch
	excluded := map[string]bool{a.NormalizeReg(a.SP()): true}
	for r := range g.Dst {
		excluded[a.NormalizeReg(r)] = true
	}
	for _, d := range g.Decodes {
		for name := range a.WrittenRegisters(d) {
			n := a.NormalizeReg(name)
			if !excluded[n] {
				g.SideRegs[n] = true
			}
		}
	}
}

func (g *Gadget) registerSet(accessor func(*disasm.Insn) map[string]bool) map[string]bool {
	a := g.Arch
	sp := a.NormalizeReg(a.SP())
	regs := map[string]bool{}
	for _, d := range g.Decodes {
		for name := range accessor(d) {
			n := a.NormalizeReg(name)
			if n != sp {
				regs[n] = true
			}
		}
	}
	return regs
}

// TupleRepr renders <op, op1[, op2], {written}, {read}>.
func (g *Gadget) TupleRepr() string {
	written := sortedKeys(g.registerSet(g.Arch.WrittenRegisters))
	read := sortedKeys(g.registerSet(g.Arch.ReadRegisters))
	parts := []string{g.Op}
	if g.hasOp1 {
		parts = append(parts, g.DispOp1)
	}
	if g.hasOp2 {
		parts = append(parts, g.DispOp2)
	}
	parts = append(parts, "{"+strings.Join(written, ", ")+"}")
	parts = append(parts, "{"+strings.Join(read, ", ")+"}")
	return "⟨" + strings.Join(parts, ", ") + "⟩"
}

// SetSlotOp1/2 record the matched operand slots (replacing field(init=False)).
func (g *Gadget) SetSlotOp1(slot, disp string) { g.SlotOp1, g.DispOp1, g.hasOp1 = slot, disp, true }
func (g *Gadget) SetSlotOp2(slot, disp string) { g.SlotOp2, g.DispOp2, g.hasOp2 = slot, disp, true }

// WritesReg reports whether the gadget writes the normalized register.
func (g *Gadget) WritesReg(normalizedReg string) bool {
	a := g.Arch
	for _, d := range g.Decodes {
		for name := range a.WrittenRegisters(d) {
			if a.NormalizeReg(name) == normalizedReg {
				return true
			}
		}
	}
	return false
}

// ResultClobbered ports Gadget.result_clobbered.
func (g *Gadget) ResultClobbered(matchedIndices []int, dstRegs map[string]bool) bool {
	if len(dstRegs) == 0 {
		return false
	}
	a := g.Arch
	writes := func(insn *disasm.Insn) map[string]bool {
		out := map[string]bool{}
		for name := range a.WrittenRegisters(insn) {
			out[a.NormalizeReg(name)] = true
		}
		return out
	}
	produced := map[string]bool{}
	last := -1
	for _, i := range matchedIndices {
		for r := range writes(g.Decodes[i]) {
			produced[r] = true
		}
		if i > last {
			last = i
		}
	}
	sp := a.NormalizeReg(a.SP())
	guarded := map[string]bool{}
	for r := range dstRegs {
		if produced[r] && r != sp {
			guarded[r] = true
		}
	}
	if len(guarded) == 0 {
		return false
	}
	// Scan the tail after the last matched index, excluding the terminator.
	clobbered := map[string]bool{}
	for i := last + 1; i < len(g.Decodes)-1; i++ {
		for r := range writes(g.Decodes[i]) {
			clobbered[r] = true
		}
	}
	for r := range guarded {
		if clobbered[r] {
			return true
		}
	}
	return false
}

// Subsumes ports Gadget.subsumes.
func (g *Gadget) Subsumes(rhs *Gadget) bool {
	if !setEqual(g.Dst, rhs.Dst) || !setEqual(g.Src, rhs.Src) {
		return false
	}
	return subset(g.SideRegs, rhs.SideRegs)
}

func (g *Gadget) base() string { return filepath.Base(g.Filename) }

// DisplayRepr dims framing instructions.
func (g *Gadget) DisplayRepr() string {
	if len(g.Frame) == 0 {
		return g.TextRepr
	}
	parts := make([]string, len(g.Decodes))
	for i, d := range g.Decodes {
		text := insnText(d)
		if i < len(g.Frame) && g.Frame[i] {
			text = colorize(text, frameColor)
		}
		parts[i] = text
	}
	return strings.Join(parts, " ; ")
}

// String ports Gadget.__str__.
func (g *Gadget) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s @ %#x]: %s", g.base(), g.Vaddr, g.DisplayRepr())
	if g.Symbol != "" {
		fmt.Fprintf(&b, " <%s>", g.Symbol)
	}
	if g.Count > 1 {
		fmt.Fprintf(&b, " (x%d)", g.Count)
	}
	if len(g.SideRegs) > 0 {
		mods := strings.Join(sortedKeys(g.SideRegs), ", ")
		b.WriteString(" " + colorize("(modifies "+mods+")", warningColor))
	}
	return b.String()
}

// ToDict is the machine-readable representation (json/csv).
func (g *Gadget) ToDict() map[string]any {
	insns := make([]string, len(g.Decodes))
	for i, d := range g.Decodes {
		insns[i] = strings.TrimSpace(insnText(d))
	}
	var bytesHex any
	if g.Bytes != nil {
		bytesHex = toHex(g.Bytes)
	}
	var dst, src any
	if len(g.Dst) > 0 {
		dst = sortedKeys(g.Dst)
	}
	if len(g.Src) > 0 {
		src = sortedKeys(g.Src)
	}
	var sym any
	if g.Symbol != "" {
		sym = g.Symbol
	}
	var op any
	if g.Op != "" {
		op = g.Op
	}
	return map[string]any{
		"file":         g.base(),
		"vaddr":        fmt.Sprintf("%#x", g.Vaddr),
		"gadget":       g.TextRepr,
		"instructions": insns,
		"bytes":        bytesHex,
		"count":        g.Count,
		"symbol":       sym,
		"op":           op,
		"dst":          dst,
		"src":          src,
		"modifies":     sortedKeys(g.SideRegs),
	}
}

// HeuristicBasicCount: lower is better (4 per side reg, 2 per instruction).
func HeuristicBasicCount(g *Gadget) int {
	return 4*len(g.SideRegs) + 2*len(g.Decodes)
}

// --- small set helpers ---

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func subset(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

const hexdigits = "0123456789abcdef"

func toHex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}
