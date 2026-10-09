// Package search holds rop4's architecture-agnostic scan strategies, ported
// from rop3/search.py. Predicates (validity, bad-char filtering, framing) are
// injected by the caller, exactly as rop3 decouples them.
package search

import (
	"github.com/reverseame/rop4/internal/disasm"
)

// Termination is one gadget-terminator byte pattern. Pattern matches a fixed
// number of consecutive bytes, one ByteClass per byte; Size is the encoded
// length of the terminator.
type Termination struct {
	Pattern []ByteClass
	Size    int
}

// ByteClass matches a single byte: any byte when Any, else one of Set.
type ByteClass struct {
	Any bool
	Set []byte
}

// Match reports whether b is in the class.
func (c ByteClass) Match(b byte) bool {
	if c.Any {
		return true
	}
	for _, x := range c.Set {
		if x == b {
			return true
		}
	}
	return false
}

// AnyByte and OneOf and Fixed build ByteClasses (used by the arch tables).
func AnyByte() ByteClass         { return ByteClass{Any: true} }
func OneOf(bs ...byte) ByteClass { return ByteClass{Set: bs} }
func Fixed(b byte) ByteClass     { return ByteClass{Set: []byte{b}} }

// maxInsnBytes: no instruction on a supported ISA is longer.
const maxInsnBytes = 16

// Match is one discovered candidate: a gadget's address, raw bytes, decoded
// instructions, and per-instruction framing mask (nil when not applicable).
type Match struct {
	Vaddr   uint64
	Raw     []byte
	Decodes []*disasm.Insn
	Frame   []bool
}

// DisasmFunc decodes raw bytes located at vaddr (capstone Cs.disasm analogue).
type DisasmFunc func(raw []byte, vaddr uint64) []*disasm.Insn

// Predicates bundles the callables galileo needs.
type Predicates struct {
	IsValidGadget         func([]*disasm.Insn) bool
	AcceptMatch           func(ref int) bool             // partition terminator end-offsets (parallel chunks)
	AcceptCandidate       func(vaddr uint64, raw []byte) bool
	RestoresReturnAddress func(*disasm.Insn) bool
}

// termEnds returns the end offsets of every non-overlapping match of one
// termination pattern in opcodes (re.finditer semantics).
func termEnds(opcodes []byte, t Termination) []int {
	var ends []int
	n := len(opcodes)
	i := 0
	for i+t.Size <= n {
		ok := true
		for k, cls := range t.Pattern {
			if !cls.Match(opcodes[i+k]) {
				ok = false
				break
			}
		}
		if ok {
			ends = append(ends, i+t.Size)
			i += t.Size // non-overlapping, advance past the match
		} else {
			i++
		}
	}
	return ends
}

// Galileo is the backward walk (rop3 search.galileo_scan). It anchors on each
// termination byte pattern and disassembles backward from it, trying every
// aligned start offset up to depth bytes, yielding every valid gadget.
func Galileo(opcodes []byte, baseVaddr uint64, terminations []Termination,
	depth, alignment int, dis DisasmFunc, p Predicates) []Match {

	var out []Match
	for _, term := range terminations {
		termSize := term.Size
		for _, ref := range termEnds(opcodes, term) {
			if p.AcceptMatch != nil && !p.AcceptMatch(ref) {
				continue
			}
			start0 := ref - termSize
			if alignment > 1 && (baseVaddr+uint64(start0))%uint64(alignment) != 0 {
				continue
			}
			for length := termSize; length <= depth; length++ {
				start := ref - length
				if start < 0 {
					continue
				}
				vaddr := baseVaddr + uint64(start)
				if alignment > 1 && vaddr%uint64(alignment) != 0 {
					continue
				}
				raw := opcodes[start:ref]
				if p.AcceptCandidate != nil && !p.AcceptCandidate(vaddr, raw) {
					continue
				}
				decodes := dis(raw, vaddr)
				if len(decodes) == 0 {
					continue
				}
				frame := make([]bool, len(decodes))
				if p.RestoresReturnAddress != nil {
					for i, insn := range decodes {
						frame[i] = p.RestoresReturnAddress(insn)
					}
				}
				if p.IsValidGadget(decodes) {
					frame[len(frame)-1] = true // terminator frames the run
					// Copy raw so later reuse of the opcodes slice is safe.
					rb := make([]byte, len(raw))
					copy(rb, raw)
					out = append(out, Match{Vaddr: vaddr, Raw: rb, Decodes: decodes, Frame: frame})
				}
			}
		}
	}
	return out
}
