package search

import (
	"github.com/reverseame/rop4/internal/disasm"
)

// LiteralCandidate is one fixed-length instruction window found by the literal
// scans: its address, the exact bytes it spans, and the decoded instructions.
type LiteralCandidate struct {
	Vaddr   uint64
	Raw     []byte
	Decodes []*disasm.Insn
}

// LiteralScan is the forward, anchor-free fixed-length window scan (ports rop3
// search.literal_scan). It tries decoding patternLen instructions starting at
// every alignment-stepped byte offset, so a pattern hiding "unintended" inside
// another instruction's encoding is still found. It stays pattern-agnostic: the
// caller applies the actual pattern-equality test via yield, which returns true
// to stop the scan (first-appearance semantics).
func LiteralScan(opcodes []byte, baseVaddr uint64, alignment int, dis DisasmFunc, patternLen int,
	acceptCandidate func(uint64, []byte) bool, yield func(LiteralCandidate) bool) {
	n := len(opcodes)
	step := alignment
	if step < 1 {
		step = 1
	}
	window := patternLen * maxInsnBytes
	for off := 0; off < n; off += step {
		vaddr := baseVaddr + uint64(off)
		end := off + window
		if end > n {
			end = n
		}
		decodes := dis(opcodes[off:end], vaddr)
		if len(decodes) < patternLen {
			continue
		}
		decodes = decodes[:patternLen]
		last := decodes[len(decodes)-1]
		rawEnd := last.Address + uint64(len(last.Bytes)) - baseVaddr
		raw := opcodes[off:rawEnd]
		if acceptCandidate != nil && !acceptCandidate(vaddr, raw) {
			continue
		}
		rb := make([]byte, len(raw))
		copy(rb, raw)
		if yield(LiteralCandidate{Vaddr: vaddr, Raw: rb, Decodes: decodes}) {
			return
		}
	}
}

// AlignedLiteralScan is the fixed-length window scan over the intended
// instruction stream, the single-pass counterpart for aligned/fixed-width ISAs
// (ports rop3 search.aligned_literal_scan). It slides a window of the last
// patternLen contiguous instructions along the linear stream; a resync gap
// breaks contiguity and resets the window. yield returns true to stop.
func AlignedLiteralScan(opcodes []byte, baseVaddr uint64, alignment int, dis DisasmFunc, patternLen int,
	acceptCandidate func(uint64, []byte) bool, yield func(LiteralCandidate) bool) {
	var window []*disasm.Insn
	for _, insn := range LinearInstructionStream(opcodes, baseVaddr, alignment, dis) {
		// A gadget's bytes must be a single contiguous run; a resync gap breaks
		// it, so restart the window.
		if len(window) > 0 {
			prev := window[len(window)-1]
			if prev.Address+uint64(len(prev.Bytes)) != insn.Address {
				window = window[:0]
			}
		}
		window = append(window, insn)
		if len(window) < patternLen {
			continue
		}
		window = window[len(window)-patternLen:] // keep only the last patternLen
		start := window[0].Address
		end := window[len(window)-1].Address + uint64(len(window[len(window)-1].Bytes))
		raw := opcodes[start-baseVaddr : end-baseVaddr]
		if acceptCandidate != nil && !acceptCandidate(start, raw) {
			continue
		}
		rb := make([]byte, len(raw))
		copy(rb, raw)
		decodes := make([]*disasm.Insn, len(window))
		copy(decodes, window)
		if yield(LiteralCandidate{Vaddr: start, Raw: rb, Decodes: decodes}) {
			return
		}
	}
}
