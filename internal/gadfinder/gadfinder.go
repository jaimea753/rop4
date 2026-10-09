// Package gadfinder orchestrates the gadget scan (ported from rop3/gadfinder.py).
// This is the serial scan path: dedup, canary-aware tiebreak, deterministic
// sort, and nearest-symbol annotation. Cache, parallel scan, operation and
// ROP-chain matching are layered on separately.
package gadfinder

import (
	"fmt"
	"os"
	"path/filepath"
	"encoding/hex"
	"sort"
	"strconv"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/cache"
	"github.com/reverseame/rop4/internal/debuglog"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/roplang"
	"github.com/reverseame/rop4/internal/search"
)

// Search flags (rop3 gadfinder constants, same values).
const (
	Default              = 0
	KeepDuplicates       = 1
	JOP                  = 2
	ROP                  = 4
	RETF                 = 8
	AllowUndeterministic = 16
	AllowComplexMem      = 32
	AvoidCanary          = 64
	AllowRetImm          = 128
	AllowRegAliases      = 256
	KeepContradictory    = 512
	Unframed             = 1024
	Ropblock             = 2048
	AllowSegmentOverride = 4096
)

// canaryBytes: terminator bytes preferred-absent in a gadget address by default.
var canaryBytes = []byte{0x00, 0x0a, 0x0d, 0xff}

// GadFinder runs gadget scans for one architecture (set on first binary).
type GadFinder struct {
	Depth int // 0 means architecture default
	Flags int
	Jobs  int

	arch     arch.Arch
	eng      *disasm.Engine
	rlParser *roplang.Parser
	cache    *cache.Cache
}

// SetCache enables the on-disk gadget cache rooted at dir ("" -> default dir).
func (gf *GadFinder) SetCache(dir string) { gf.cache = cache.New(dir) }

// New builds a finder.
func New(depth, flags, jobs int) *GadFinder {
	if jobs < 1 {
		jobs = 1
	}
	return &GadFinder{Depth: depth, Flags: flags, Jobs: jobs}
}

// Arch returns the architecture detected from the scanned binaries.
func (gf *GadFinder) Arch() arch.Arch { return gf.arch }

// FindOpts carries the per-run scan options.
type FindOpts struct {
	Bases        []string // one per filename, or nil
	Badchars     []string
	BadcharBytes []string
	ArchName     string
	Symbols      bool
	Raw          bool
}

func (gf *GadFinder) has(flag int) bool { return gf.Flags&flag != 0 }

// Find scans the named binaries and returns the (deduplicated, sorted) gadgets.
func (gf *GadFinder) Find(filenames []string, opt FindOpts) ([]*gadget.Gadget, error) {
	if gf.has(Ropblock) {
		return nil, fmt.Errorf("--ropblock not yet implemented")
	}
	bases := gf.normalizeBases(opt.Bases, len(filenames))

	if gf.has(KeepDuplicates) {
		var all []*gadget.Gadget
		for i, fn := range filenames {
			gs, err := gf.scanFile(fn, bases[i], opt)
			if err != nil {
				return nil, err
			}
			all = append(all, gs...)
		}
		gf.sortGadgets(all)
		return all, nil
	}

	seen := map[string]*gadget.Gadget{}
	avoid := gf.avoidBytes(opt.Badchars)
	total := 0
	for i, fn := range filenames {
		gs, err := gf.scanFile(fn, bases[i], opt)
		if err != nil {
			return nil, err
		}
		for _, g := range gs {
			total++
			key := g.Key()
			if existing, ok := seen[key]; !ok {
				g.Count = 1
				seen[key] = g
			} else {
				existing.Count++
				if gf.has(AvoidCanary) {
					ns, na := gf.addrCanaryScore(g, avoid), g.Vaddr
					cs, ca := gf.addrCanaryScore(existing, avoid), existing.Vaddr
					if ns < cs || (ns == cs && na < ca) {
						g.Count = existing.Count
						seen[key] = g
					}
				}
			}
		}
	}
	if total > 0 || len(seen) > 0 {
		debuglog.Info("%d unique gadgets (%d duplicates discarded)", len(seen), total-len(seen))
	}
	out := make([]*gadget.Gadget, 0, len(seen))
	for _, g := range seen {
		out = append(out, g)
	}
	gf.sortGadgets(out)
	return out, nil
}

func (gf *GadFinder) normalizeBases(bases []string, n int) []string {
	out := make([]string, n)
	for i := range out {
		if i < len(bases) {
			out[i] = bases[i]
		}
	}
	return out
}

func (gf *GadFinder) scanFile(filename, base string, opt FindOpts) ([]*gadget.Gadget, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to read file", filename)
	}
	bin, err := binfmt.Load(data, base, opt.ArchName, opt.Raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filename, err)
	}
	a := bin.Arch()
	if gf.arch != nil {
		if gf.arch.CSArch() != a.CSArch() || gf.arch.CSMode() != a.CSMode() {
			return nil, fmt.Errorf("%s: mixing architectures in a single run is not supported", filename)
		}
	} else {
		gf.arch = a
		eng, err := disasm.Open(a.CSArch(), a.CSMode())
		if err != nil {
			return nil, err
		}
		gf.eng = eng
	}
	depth := gf.Depth
	if depth <= 0 {
		depth = a.DefaultDepth()
	}

	var symTab *symbolTable
	if opt.Symbols {
		symTab = newSymbolTable(bin.Symbols())
	}

	dis := func(raw []byte, vaddr uint64) []*disasm.Insn {
		insns, _ := gf.eng.Disasm(raw, vaddr, 0)
		return insns
	}
	terms := gf.gadTerminations(a)
	isValid := gf.makeIsValidGadget(a)
	acceptCandidate := func(vaddr uint64, raw []byte) bool {
		return gf.isValidAddress(vaddr, opt.Badchars, a.AddressSize()) &&
			gf.isValidBytes(raw, opt.BadcharBytes)
	}

	// Cache lookup.
	var key string
	if gf.cache != nil {
		k, err := gf.cache.Key(cache.FileHash(data), gf.recordParams(bin, depth, a, opt))
		if err == nil {
			key = k
			if recs, ok := gf.cache.Load(key); ok {
				debuglog.Info("%s: %d gadgets from cache", filepath.Base(filename), len(recs))
				return gf.reconstruct(filename, a, recs, symTab), nil
			}
		}
	}

	// Gather matches, serially or (x86 Galileo only) across worker goroutines.
	var matches []search.Match
	parallelizable := a.Parallelizable() && !gf.has(Ropblock)
	if gf.Jobs > 1 && parallelizable {
		matches = gf.parallelScan(bin, a, depth, terms, isValid, acceptCandidate)
	} else {
		if gf.Jobs > 1 {
			debuglog.Info("%s scan runs single-threaded; --jobs ignored", a.ScanName(gf.has(Ropblock), gf.framed()))
		}
		for _, sec := range bin.ExecSections() {
			matches = append(matches, a.Scan(sec.Opcodes, sec.Vaddr, depth, dis, isValid, terms,
				acceptCandidate, gf.framed(), gf.has(Ropblock), nil)...)
		}
	}

	out := make([]*gadget.Gadget, 0, len(matches))
	var records []cache.Record
	for _, m := range matches {
		sym := ""
		if symTab != nil {
			sym = symTab.nearest(m.Vaddr)
		}
		g := gadget.New(filename, a, m.Vaddr, m.Decodes, m.Raw, m.Frame)
		g.Symbol = sym
		out = append(out, g)
		if gf.cache != nil {
			records = append(records, cache.Record{Vaddr: m.Vaddr, Hex: hex.EncodeToString(m.Raw), Frame: m.Frame})
		}
	}
	if gf.cache != nil && key != "" {
		if err := gf.cache.Store(key, records); err != nil {
			debuglog.Warning("%s", err)
		}
	}
	return out, nil
}

// reconstruct rebuilds gadgets from cached records (rop3 _reconstruct).
func (gf *GadFinder) reconstruct(filename string, a arch.Arch, recs []cache.Record, symTab *symbolTable) []*gadget.Gadget {
	out := make([]*gadget.Gadget, 0, len(recs))
	for _, rec := range recs {
		raw, err := hex.DecodeString(rec.Hex)
		if err != nil {
			continue
		}
		decodes, _ := gf.eng.Disasm(raw, rec.Vaddr, 0)
		sym := ""
		if symTab != nil {
			sym = symTab.nearest(rec.Vaddr)
		}
		g := gadget.New(filename, a, rec.Vaddr, decodes, raw, rec.Frame)
		g.Symbol = sym
		out = append(out, g)
	}
	return out
}

// recordParams mirrors rop3 _record_params: everything besides file content
// that changes the record set, so a different option misses the cache.
func (gf *GadFinder) recordParams(bin binfmt.Binary, depth int, a arch.Arch, opt FindOpts) map[string]any {
	var secs [][]int
	for _, s := range bin.ExecSections() {
		secs = append(secs, []int{int(s.Vaddr), len(s.Opcodes)})
	}
	bc := append([]string(nil), opt.Badchars...)
	sort.Strings(bc)
	bcb := append([]string(nil), opt.BadcharBytes...)
	sort.Strings(bcb)
	return map[string]any{
		"record_version": 2,
		"depth":          depth,
		"flags":          gf.Flags,
		"arch":           []int{int(a.CSArch()), int(a.CSMode())},
		"badchars":       bc,
		"badchar_bytes":  bcb,
		"sections":       secs,
	}
}

func (gf *GadFinder) framed() bool { return !gf.has(Unframed) }

// gadTerminations builds the termination byte patterns (rop3 _gad_terminations).
func (gf *GadFinder) gadTerminations(a arch.Arch) []search.Termination {
	var ret []search.Termination
	retImm := gf.has(AllowRetImm)
	if gf.has(ROP) {
		ret = append(ret, a.GetROPTerminations(false, retImm)...)
	}
	if gf.has(RETF) {
		ret = append(ret, a.GetROPTerminations(true, retImm)...)
	}
	if gf.has(JOP) {
		ret = append(ret, a.GetJOPTerminations()...)
	}
	return ret
}

// makeIsValidGadget mirrors GadFinder._is_valid_gadget.
func (gf *GadFinder) makeIsValidGadget(a arch.Arch) func([]*disasm.Insn) bool {
	allowUndet := gf.has(AllowUndeterministic)
	allowRetImm := gf.has(AllowRetImm)
	return func(decodes []*disasm.Insn) bool {
		if len(decodes) == 0 {
			return false
		}
		ret := false
		if gf.has(ROP) {
			ret = ret || a.IsValidROPGadget(decodes, allowUndet, allowRetImm, false)
		}
		if gf.has(RETF) {
			ret = ret || a.IsValidROPGadget(decodes, allowUndet, allowRetImm, true)
		}
		if !ret && gf.has(JOP) {
			ret = ret || a.IsValidJOPGadget(decodes, allowUndet)
		}
		if ret && !gf.has(AllowComplexMem) && a.FirstInsnHasComplexMem(decodes) {
			return false
		}
		if ret && !gf.has(AllowSegmentOverride) && a.FirstInsnHasSegmentOverride(decodes) {
			return false
		}
		return ret
	}
}

func (gf *GadFinder) avoidBytes(badchars []string) map[byte]bool {
	out := map[byte]bool{}
	if len(badchars) > 0 {
		for _, bc := range badchars {
			if v, err := strconv.ParseUint(bc, 0, 8); err == nil {
				out[byte(v)] = true
			}
		}
		return out
	}
	for _, b := range canaryBytes {
		out[b] = true
	}
	return out
}

func (gf *GadFinder) addrCanaryScore(g *gadget.Gadget, avoid map[byte]bool) int {
	packed := packAddr(g.Vaddr, gf.arch.AddressSize())
	n := 0
	for _, b := range packed {
		if avoid[b] {
			n++
		}
	}
	return n
}

func (gf *GadFinder) sortGadgets(gs []*gadget.Gadget) {
	sort.SliceStable(gs, func(i, j int) bool {
		bi, bj := filepath.Base(gs[i].Filename), filepath.Base(gs[j].Filename)
		if bi != bj {
			return bi < bj
		}
		return gs[i].Vaddr < gs[j].Vaddr
	})
}

func (gf *GadFinder) isValidAddress(vaddr uint64, badchars []string, size int) bool {
	if len(badchars) == 0 {
		return true
	}
	packed := packAddr(vaddr, size)
	for _, bc := range badchars {
		v, err := strconv.ParseUint(bc, 0, 8)
		if err != nil {
			continue
		}
		for _, b := range packed {
			if b == byte(v) {
				return false
			}
		}
	}
	return true
}

func (gf *GadFinder) isValidBytes(gadgetBytes []byte, badcharBytes []string) bool {
	if len(badcharBytes) == 0 {
		return true
	}
	forbidden := map[byte]bool{}
	for _, b := range badcharBytes {
		if v, err := strconv.ParseUint(b, 0, 8); err == nil {
			forbidden[byte(v)] = true
		}
	}
	for _, b := range gadgetBytes {
		if forbidden[b] {
			return false
		}
	}
	return true
}

// packAddr little-endian packs addr into size bytes (rop3 utils.pack_addr).
func packAddr(addr uint64, size int) []byte {
	out := make([]byte, size)
	for i := 0; i < size; i++ {
		out[i] = byte(addr >> (8 * i))
	}
	return out
}

// symbolTable supports nearest-symbol lookup (rop3 _symbol_table/_nearest_symbol).
type symbolTable struct {
	addrs []uint64
	names []string
}

func newSymbolTable(syms []binfmt.Symbol) *symbolTable {
	sort.Slice(syms, func(i, j int) bool {
		if syms[i].Addr != syms[j].Addr {
			return syms[i].Addr < syms[j].Addr
		}
		return syms[i].Name < syms[j].Name
	})
	st := &symbolTable{}
	for _, s := range syms {
		st.addrs = append(st.addrs, s.Addr)
		st.names = append(st.names, s.Name)
	}
	return st
}

func (st *symbolTable) nearest(vaddr uint64) string {
	// index of the last addr <= vaddr (bisect_right - 1)
	idx := sort.Search(len(st.addrs), func(i int) bool { return st.addrs[i] > vaddr }) - 1
	if idx < 0 {
		return ""
	}
	off := vaddr - st.addrs[idx]
	if off != 0 {
		return fmt.Sprintf("%s+%#x", st.names[idx], off)
	}
	return st.names[idx]
}
