package gadfinder

import (
	"math"
	"sync"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/search"
)

// chunkTask is one section slice scanned by one worker. Only terminations
// ending in [emitLo, emitHi) are emitted, so chunks never double-count a gadget
// (rop3 search.scan_parallel / _scan_chunk).
type chunkTask struct {
	slice      []byte
	baseVaddr  uint64
	sliceStart int
	emitLo     int
	emitHi     int
}

// parallelScan runs the Galileo backward walk across gf.Jobs worker goroutines
// (x86 only; fixed-width ISAs set Parallelizable()=false and never reach here).
// Each worker owns its own capstone engine. Output is the same multiset as the
// serial scan; determinism comes from the dedup + final sort in Find.
func (gf *GadFinder) parallelScan(bin binfmt.Binary, a arch.Arch, depth int,
	terms []search.Termination, isValid func([]*disasm.Insn) bool,
	acceptCandidate func(uint64, []byte) bool) []search.Match {

	var tasks []chunkTask
	for _, sec := range bin.ExecSections() {
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
				slice:      sec.Opcodes[start:hi],
				baseVaddr:  sec.Vaddr + uint64(start),
				sliceStart: start,
				emitLo:     lo,
				emitHi:     emitHi,
			})
		}
	}
	if len(tasks) == 0 {
		return nil
	}

	taskCh := make(chan chunkTask)
	var mu sync.Mutex
	var out []search.Match
	var wg sync.WaitGroup
	align := a.Alignment()
	restoresRA := a.RestoresReturnAddress

	worker := func() {
		defer wg.Done()
		eng, err := disasm.Open(a.CSArch(), a.CSMode())
		if err != nil {
			return
		}
		defer eng.Close()
		dis := func(raw []byte, vaddr uint64) []*disasm.Insn {
			insns, _ := eng.Disasm(raw, vaddr, 0)
			return insns
		}
		for t := range taskCh {
			t := t
			acceptMatch := func(ref int) bool {
				abs := t.sliceStart + ref
				return t.emitLo <= abs && abs < t.emitHi
			}
			ms := search.Galileo(t.slice, t.baseVaddr, terms, depth, align, dis, search.Predicates{
				IsValidGadget:         isValid,
				AcceptMatch:           acceptMatch,
				AcceptCandidate:       acceptCandidate,
				RestoresReturnAddress: restoresRA,
			})
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
