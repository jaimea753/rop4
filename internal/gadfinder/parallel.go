package gadfinder

import (
	"math"
	"sync"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// chunkTask is one section slice scanned by one worker. For the chunkable x86
// Galileo walk, only terminations ending in [emitLo, emitHi) are emitted, so
// chunks never double-count a gadget (rop3 search.scan_parallel / _scan_chunk).
// For fixed-width ISAs the whole section is one task (section=true).
type chunkTask struct {
	slice      []byte
	baseVaddr  uint64
	sliceStart int
	emitLo     int
	emitHi     int
	section    bool // whole-section aligned scan (fixed-width), not a Galileo chunk
}

// parallelScan runs the gadget scan across gf.Jobs worker goroutines, each with
// its own capstone engine. x86 (Parallelizable) is chunked within sections via
// the Galileo backward walk; fixed-width ISAs are split one task per section.
// Output is the same multiset as the serial scan; determinism comes from the
// dedup + final sort in Find.
func (gf *GadFinder) parallelScan(bin binfmt.Binary, a arch.Arch, depth int, dis search.DisasmFunc,
	terms []search.Termination, isValid func([]*disasm.Insn) bool,
	acceptCandidate func(uint64, []byte) bool) []search.Match {

	chunkable := a.Parallelizable()
	var tasks []chunkTask
	for _, sec := range bin.ExecSections() {
		if !chunkable {
			tasks = append(tasks, chunkTask{slice: sec.Opcodes, baseVaddr: sec.Vaddr, section: true})
			continue
		}
		n := len(sec.Opcodes)
		chunk := int(math.Ceil(float64(n) / float64(gf.Jobs*4)))
		if chunk < 4096 {
			chunk = 4096
		}
		for lo := 0; lo < n; lo += chunk {
			hi := lo + chunk
			if hi > n {
				hi = n
			}
			start := lo - depth
			if start < 0 {
				start = 0
			}
			emitHi := hi
			if hi == n { // the last chunk also owns the closing offset n
				emitHi = hi + 1
			}
			tasks = append(tasks, chunkTask{
				slice: sec.Opcodes[start:hi], baseVaddr: sec.Vaddr + uint64(start),
				sliceStart: start, emitLo: lo, emitHi: emitHi,
			})
		}
	}
	if len(tasks) == 0 {
		return nil
	}

	framed := gf.framed()
	align := a.Alignment()
	restoresRA := a.RestoresReturnAddress

	taskCh := make(chan chunkTask)
	var mu sync.Mutex
	var out []search.Match
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		eng, err := disasm.Open(a.CSArch(), a.CSMode())
		if err != nil {
			return
		}
		defer eng.Close()
		wdis := func(raw []byte, vaddr uint64) []*disasm.Insn {
			insns, _ := eng.Disasm(raw, vaddr, 0)
			return insns
		}
		for t := range taskCh {
			var ms []search.Match
			if t.section {
				// Fixed-width: a whole-section aligned scan (ropblock excluded here).
				ms = a.Scan(t.slice, t.baseVaddr, depth, wdis, isValid, terms,
					acceptCandidate, framed, false, nil)
			} else {
				t := t
				acceptMatch := func(ref int) bool {
					abs := t.sliceStart + ref
					return t.emitLo <= abs && abs < t.emitHi
				}
				ms = search.Galileo(t.slice, t.baseVaddr, terms, depth, align, wdis, search.Predicates{
					IsValidGadget:         isValid,
					AcceptMatch:           acceptMatch,
					AcceptCandidate:       acceptCandidate,
					RestoresReturnAddress: restoresRA,
				})
			}
			if len(ms) > 0 {
				mu.Lock()
				out = append(out, ms...)
				mu.Unlock()
			}
		}
	}

	nw := gf.Jobs
	if nw > len(tasks) {
		nw = len(tasks)
	}
	wg.Add(nw)
	for i := 0; i < nw; i++ {
		go worker()
	}
	for _, t := range tasks {
		taskCh <- t
	}
	close(taskCh)
	wg.Wait()
	return out
}
