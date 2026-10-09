package search

import (
	"github.com/reverseame/rop4/internal/disasm"
)

// BackInsn is one backward-iterated instruction: the byte offset it begins at
// and the single instruction decoded there.
type BackInsn struct {
	Off  int
	Insn *disasm.Insn
}

// BackwardInstructions is the arch-aware backward instruction iterator (ports
// rop3 search.backward_instructions). Starting just below start (len(opcodes)
// by default when start < 0) and stepping toward the front by alignment, it
// decodes the single instruction that begins at each aligned offset and returns
// (offset, insn). Offsets where nothing decodes are skipped.
func BackwardInstructions(opcodes []byte, baseVaddr uint64, alignment int, dis DisasmFunc, start int) []BackInsn {
	hi := len(opcodes)
	if start >= 0 && start < hi {
		hi = start
	}
	off := hi - 1
	if off >= 0 && alignment > 1 {
		off -= int((baseVaddr + uint64(off)) % uint64(alignment))
	}
	var out []BackInsn
	for off >= 0 {
		end := off + maxInsnBytes
		if end > len(opcodes) {
			end = len(opcodes)
		}
		decodes := dis(opcodes[off:end], baseVaddr+uint64(off))
		if len(decodes) > 0 {
			out = append(out, BackInsn{Off: off, Insn: decodes[0]})
		}
		off -= alignment
	}
	return out
}

// FramedPredicates bundles the arch-derived callables the backward framed
// (ropblock) search needs. BranchReg returns (reg, ok); ok=false marks a
// self-framing terminator (x86 ret) whose prologue is the terminator itself.
type FramedPredicates struct {
	IsTerminator    func(*disasm.Insn) bool
	BranchReg       func(*disasm.Insn) (string, bool)
	IsPrologue      func(insn *disasm.Insn, reg string) bool
	Clobbers        func(insn *disasm.Insn, reg string) bool
	IsFrame         func(*disasm.Insn) bool               // optional
	Splits          func(*disasm.Insn) bool               // optional
	AcceptCandidate func(vaddr uint64, raw []byte) bool    // optional
	AcceptDecodes   func([]*disasm.Insn) bool              // optional
}

// BackwardsFramedSearch is the backward framed ("ropblock") gadget search
// (ports rop3 search.backwards_framed_search). A ropblock gadget is framed as
// [prologue] ... [terminator]: the terminator writes the program counter from a
// register, and the prologue loads that register from the stack. x86 ret is the
// degenerate self-framing case.
//
// It returns every framed run (each carrying a per-instruction frame mask), in
// the same order rop3 yields them: terminators from the high end of the buffer
// toward the front, and for each terminator candidate lengths from the
// terminator size up to depth.
func BackwardsFramedSearch(opcodes []byte, baseVaddr uint64, depth, alignment int,
	dis DisasmFunc, p FramedPredicates) []Match {

	var out []Match
	for _, bi := range BackwardInstructions(opcodes, baseVaddr, alignment, dis, -1) {
		tOff, term := bi.Off, bi.Insn
		if !p.IsTerminator(term) {
			continue
		}
		termEnd := tOff + len(term.Bytes)
		// Grow the candidate backward from the terminator, one length at a time.
		for length := len(term.Bytes); length <= depth; length++ {
			q := termEnd - length
			if q < 0 {
				break
			}
			if alignment > 1 && (baseVaddr+uint64(q))%uint64(alignment) != 0 {
				continue
			}
			raw := opcodes[q:termEnd]
			if p.AcceptCandidate != nil && !p.AcceptCandidate(baseVaddr+uint64(q), raw) {
				continue
			}
			decodes := dis(raw, baseVaddr+uint64(q))
			if len(decodes) == 0 {
				continue
			}
			last := decodes[len(decodes)-1]
			// The run must decode cleanly and still end on the terminator.
			if last.Address+uint64(len(last.Bytes)) != baseVaddr+uint64(termEnd) {
				continue
			}
			if !p.IsTerminator(last) {
				continue
			}
			// No control-flow transfer before the terminator.
			if p.Splits != nil {
				split := false
				for _, insn := range decodes[:len(decodes)-1] {
					if p.Splits(insn) {
						split = true
						break
					}
				}
				if split {
					continue
				}
			}
			reg, regOK := p.BranchReg(last)
			prologue, ok := RopblockPrologueIndex(decodes, reg, regOK, p.IsPrologue, p.Clobbers)
			if !ok {
				continue // not framed
			}
			if p.AcceptDecodes != nil && !p.AcceptDecodes(decodes) {
				continue // supplementary body filter
			}
			frame := FrameMask(decodes, prologue, p.IsFrame)
			rb := make([]byte, len(raw))
			copy(rb, raw)
			out = append(out, Match{Vaddr: baseVaddr + uint64(q), Raw: rb, Decodes: decodes, Frame: frame})
		}
	}
	return out
}

// RopblockPrologueIndex returns the index of the prologue that frames the run
// (whose last instruction is the terminator), and ok=false when it is not
// framed (ports rop3 search._ropblock_prologue_index). When regOK is false the
// terminator is self-framing (x86 ret): its own index frames the run.
func RopblockPrologueIndex(decodes []*disasm.Insn, reg string, regOK bool,
	isPrologue func(*disasm.Insn, string) bool, clobbers func(*disasm.Insn, string) bool) (int, bool) {
	if !regOK {
		return len(decodes) - 1, true // x86 ret: its own prologue
	}
	for i := len(decodes) - 2; i >= 0; i-- {
		if isPrologue(decodes[i], reg) {
			return i, true
		}
		if clobbers(decodes[i], reg) {
			return 0, false
		}
	}
	return 0, false
}

// FrameMask builds the per-instruction framing mask: the prologue, the
// terminator (last), and any position-independent framing instruction isFrame
// recognizes (ports rop3 search._frame_mask).
func FrameMask(decodes []*disasm.Insn, prologue int, isFrame func(*disasm.Insn) bool) []bool {
	last := len(decodes) - 1
	mask := make([]bool, len(decodes))
	for i, insn := range decodes {
		mask[i] = i == prologue || i == last || (isFrame != nil && isFrame(insn))
	}
	return mask
}
