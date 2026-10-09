package gadfinder

import (
	"fmt"
	"os"

	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/operation"
	"github.com/reverseame/rop4/internal/search"
)

// FindRawGadgets scans the binaries for defn's verbatim instruction pattern (a
// raw(...) chain step's single realization) and returns one synthetic Gadget per
// binary -- the first appearance. Ports rop3 GadFinder.find_raw_gadgets.
//
// This bypasses the normal backward gadget scan, which structurally only ever
// emits candidates ending on a valid ROP/JOP terminator, so a raw gadget with
// no ret/branch terminator (e.g. a bare syscall / svc 0 / ecall) can be found.
//
// Deviation from rop3: Keystone is dropped in rop4 (no external dependency), so
// the fast assemble+byte-regex path is never taken -- rop4 always uses the
// Capstone disassembly scan (search.LiteralScan on x86, search.AlignedLiteralScan
// on fixed-width ISAs). That matches rop3's own behaviour when Keystone is
// unavailable, where the disassembly scan is the sole path and never turns a
// real hit into a miss.
//
// Returned Gadgets carry frame = (false,)*patternLen -- deliberately not a mask
// that marks the last position as framing, since that would make a single-
// instruction pattern permanently unmatchable.
func (gf *GadFinder) FindRawGadgets(filenames []string, defn *operation.OperationDef, opt FindOpts) ([]*gadget.Gadget, error) {
	pattern := defn.RawPattern()
	if pattern == nil {
		return nil, fmt.Errorf("raw gadget has no pattern")
	}
	patternLen := len(pattern.Items)
	bases := gf.normalizeBases(opt.Bases, len(filenames))

	var ret []*gadget.Gadget
	for i, filename := range filenames {
		data, err := os.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to read file", filename)
		}
		bin, err := binfmt.Load(data, bases[i], opt.ArchName, opt.Raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filename, err)
		}
		a := bin.Arch()
		eng, err := gf.engineFor(a)
		if err != nil {
			return nil, err
		}
		dis := func(raw []byte, vaddr uint64) []*disasm.Insn {
			insns, _ := eng.Disasm(raw, vaddr, 0)
			return insns
		}
		acceptCandidate := func(vaddr uint64, raw []byte) bool {
			return gf.isValidAddress(vaddr, opt.Badchars, a.AddressSize()) &&
				gf.isValidBytes(raw, opt.BadcharBytes)
		}

		var found *gadget.Gadget
		match := func(c search.LiteralCandidate) bool {
			if !pattern.MatchesExactly(a, gf.has(AllowRegAliases), c.Decodes) {
				return false // keep scanning
			}
			frame := make([]bool, patternLen)
			found = gadget.New(filename, a, c.Vaddr, c.Decodes, c.Raw, frame)
			return true // first appearance -- stop
		}

		for _, sec := range bin.ExecSections() {
			if a.Alignment() == 1 {
				search.LiteralScan(sec.Opcodes, sec.Vaddr, a.Alignment(), dis, patternLen, acceptCandidate, match)
			} else {
				search.AlignedLiteralScan(sec.Opcodes, sec.Vaddr, a.Alignment(), dis, patternLen, acceptCandidate, match)
			}
			if found != nil {
				break
			}
		}
		if found != nil {
			ret = append(ret, found)
		}
	}
	return ret, nil
}

// engineFor returns a disasm engine for a, reusing the finder's engine when it
// matches the already-detected architecture, otherwise opening a fresh one.
func (gf *GadFinder) engineFor(a interface {
	CSArch() disasm.Arch
	CSMode() disasm.Mode
}) (*disasm.Engine, error) {
	if gf.eng != nil && gf.arch != nil &&
		gf.arch.CSArch() == a.CSArch() && gf.arch.CSMode() == a.CSMode() {
		return gf.eng, nil
	}
	return disasm.Open(a.CSArch(), a.CSMode())
}
