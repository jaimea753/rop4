package search

import (
	"github.com/reverseame/rop4/internal/disasm"
)

// scanChunkSize bounds the native allocation a single disasm() call makes (see
// rop3 search._SCAN_CHUNK_SIZE): capstone decodes its entire input eagerly in
// C, so a whole multi-ten-MB section would materialize at once. Chunking with a
// small overlap tail keeps peak memory bounded while leaving the yielded stream
// identical to decoding the whole section.
const scanChunkSize = 1 << 20

// LinearInstructionStream disassembles opcodes as the intended instruction
// stream, in program order (ports rop3 search._linear_instruction_stream /
// linear_instructions). Capstone stops at the first byte it cannot decode; the
// sweep resynchronizes by skipping one aligned unit past the offending byte and
// resumes.
func LinearInstructionStream(opcodes []byte, baseVaddr uint64, alignment int, dis DisasmFunc) []*disasm.Insn {
	n := len(opcodes)
	step := alignment
	if step < 1 {
		step = 1
	}
	var out []*disasm.Insn
	off := 0
	for off < n {
		coreEnd := off + scanChunkSize
		if coreEnd > n {
			coreEnd = n
		}
		chunkEnd := coreEnd + maxInsnBytes
		if chunkEnd > n {
			chunkEnd = n
		}
		coreSize := coreEnd - off
		produced := 0
		for _, insn := range dis(opcodes[off:chunkEnd], baseVaddr+uint64(off)) {
			// An instruction that starts in the overlap tail is left for the
			// next chunk (which starts exactly at coreEnd) to decode with full
			// lookahead, so the split is invisible to the yielded stream.
			if int(insn.Address-(baseVaddr+uint64(off))) >= coreSize && coreEnd < n {
				break
			}
			out = append(out, insn)
			produced += len(insn.Bytes)
		}
		// Resume right after the decoded run; if nothing decoded (bad byte at
		// off), skip one aligned unit to move past it.
		if produced != 0 {
			off += produced
		} else {
			off += step
		}
		if alignment > 1 && off%alignment != 0 {
			off += alignment - (off % alignment)
		}
	}
	return out
}

// AlignedScan is the aligned (intended-instruction) gadget search, the port of
// rop3 search.aligned_scan. It disassembles each section once as a linear
// instruction stream, then, for every instruction that is itself a valid
// termination, walks backward over the preceding whole instructions (never
// splitting one), emitting each contiguous run up to depth bytes.
//
// Framing: when isReturn is non-nil, a return terminator is emitted only once
// the backward walk has covered a return-address restore (restoresReturnAddress);
// non-return terminators (indirect JOP branches) carry no such requirement. When
// isReturn is nil the scan degrades to the plain sweep.
func AlignedScan(opcodes []byte, baseVaddr uint64, depth, alignment int, dis DisasmFunc,
	isValidGadget func([]*disasm.Insn) bool,
	restoresReturnAddress func(*disasm.Insn) bool,
	isReturn func(*disasm.Insn) bool,
	acceptCandidate func(uint64, []byte) bool) []Match {

	stream := LinearInstructionStream(opcodes, baseVaddr, alignment, dis)
	var out []Match
	for ti := 0; ti < len(stream); ti++ {
		terminator := stream[ti]
		// A termination is any instruction that is a valid gadget on its own.
		if !isValidGadget([]*disasm.Insn{terminator}) {
			continue
		}
		termEnd := terminator.Address + uint64(len(terminator.Bytes))
		requiresFrame := isReturn != nil && isReturn(terminator)

		// Walk backward over the contiguous run of intended instructions,
		// growing the frame mask at its front to stay parallel to the candidate.
		frameLoaded := false
		var frame []bool
		for idx := ti; idx >= 0; idx-- {
			insnJ := stream[idx]
			// Stop at a discontinuity (a resync gap): a gadget's bytes must be a
			// single contiguous run.
			if idx < ti && insnJ.Address+uint64(len(insnJ.Bytes)) != stream[idx+1].Address {
				break
			}
			if termEnd-insnJ.Address > uint64(depth) {
				break
			}

			// Prepending insnJ: it is framing if it restores the return address;
			// once covered, the whole (and every longer) run establishes its frame.
			isRestore := restoresReturnAddress != nil && restoresReturnAddress(insnJ)
			if isRestore {
				frameLoaded = true
			}
			frame = append([]bool{isRestore}, frame...)

			if frameLoaded || !requiresFrame {
				vaddr := insnJ.Address
				raw := opcodes[vaddr-baseVaddr : termEnd-baseVaddr]
				if acceptCandidate == nil || acceptCandidate(vaddr, raw) {
					candidate := stream[idx : ti+1]
					if isValidGadget(candidate) {
						mask := make([]bool, len(frame))
						copy(mask, frame)
						mask[len(mask)-1] = true // the terminator frames the run
						rb := make([]byte, len(raw))
						copy(rb, raw)
						cand := make([]*disasm.Insn, len(candidate))
						copy(cand, candidate)
						out = append(out, Match{Vaddr: vaddr, Raw: rb, Decodes: cand, Frame: mask})
					}
				}
			}
		}
	}
	return out
}
