// Command rop4 is the CLI entry point (ports rop3.py + rop3/__init__.main and
// a subset of rop3/args.py). The gadget-dump, operation and ROP-chain dispatch
// grows as the corresponding packages land; this stage supports the gadget
// dump across text/json/csv/tuple.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"errors"

	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/debuglog"
	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/output"
	"github.com/reverseame/rop4/internal/ropchain"
)

type args struct {
	binary       []string
	base         []string
	badchar      []string
	badcharBytes []string
	arch         string
	raw          bool
	symbols      bool
	all          bool
	depth        int
	rop          bool
	jop          bool
	retf         bool
	retImm       bool
	frame        bool
	regAliases   bool
	allowUndet   bool
	allowComplex bool
	allowSeg     bool
	keepContra   bool
	keepCanary   bool
	outputFmt    string
	tuple        bool
	cache        bool
	cacheDir     string
	verbose      bool
	version      bool
	op           string
	operands     []string
	ropchainFile string
	exhaustive   bool
	legacyChain  bool
	dst          string
	src          string
	hasDst       bool
	hasSrc       bool
}

func main() {
	a, err := parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %s\n", toolName(), err)
		os.Exit(2)
	}
	if a.version {
		fmt.Printf("%s v%s\n", toolName(), output.Version)
		return
	}
	if len(a.binary) == 0 {
		fmt.Fprintf(os.Stderr, "%s: error: --binary is required\n", toolName())
		os.Exit(2)
	}

	flags := a.toFlags()
	if a.verbose {
		debuglog.SetVerbose(true)
		a.printVerboseSummary(flags)
	}
	gf := gadfinder.New(a.depth, flags, 1)
	if a.cache {
		gf.SetCache(a.cacheDir)
	}
	gadgets, err := gf.Find(a.binary, gadfinder.FindOpts{
		Bases: a.base, Badchars: a.badchar, BadcharBytes: a.badcharBytes,
		ArchName: a.arch, Symbols: a.symbols, Raw: a.raw,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %s\n", toolName(), err)
		os.Exit(1)
	}

	outFmt := a.outputFmt
	if a.tuple {
		outFmt = "tuple"
	}

	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "%s: error: %s\n", toolName(), err)
		os.Exit(1)
	}

	switch {
	case a.ropchainFile != "":
		// Non-exhaustive text/tuple consumes only the first chain (rop3).
		limit := 0
		if !a.exhaustive && (outFmt == "text" || outFmt == "tuple") {
			limit = 1
		}
		chains, err := ropchain.New(gf).SearchFromGadgets(gadgets, a.ropchainFile, a.legacyChain, limit)
		if err != nil {
			var rcnf *gadfinder.RopChainNotFound
			if errors.As(err, &rcnf) {
				fail(fmt.Errorf("No ROP chain found: %s", rcnf.Error()))
			}
			fail(err)
		}
		if err := output.Ropchains(os.Stdout, chains, outFmt, a.exhaustive); err != nil {
			fail(err)
		}
	case a.op != "":
		result, err := gf.FindOp(gadgets, a.op, a.operands)
		if err == nil {
			if err := output.Gadgets(os.Stdout, result, outFmt); err != nil {
				fail(err)
			}
			return
		}
		// A compound operation expands into ROP chains (rop3 find_op_from_gadgets).
		if errors.Is(err, gadfinder.ErrCompoundUnsupported) {
			step := gadfinder.ChainStep{Op: a.op, Operands: a.operands,
				Data: a.op + "(" + joinComma(a.operands) + ")"}
			chains, cerr := ropchain.New(gf).Search(gadgets, []gadfinder.ChainStep{step}, false, false, 0)
			if cerr != nil {
				var rcnf *gadfinder.RopChainNotFound
				if errors.As(cerr, &rcnf) {
					// No chains: rop3 returns an empty list (no error) for compound --op.
					chains = nil
				} else {
					fail(cerr)
				}
			}
			// rop3 gates on `result and isinstance(result[0], list)`: an empty
			// compound result falls back to the plain (empty) gadget output.
			if len(chains) == 0 {
				if err := output.Gadgets(os.Stdout, nil, outFmt); err != nil {
					fail(err)
				}
				return
			}
			if err := output.Ropchains(os.Stdout, chains, outFmt, true); err != nil {
				fail(err)
			}
			return
		}
		fail(err)
	default:
		if err := output.Gadgets(os.Stdout, gadgets, outFmt); err != nil {
			fail(err)
		}
	}
}

func joinComma(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func toolName() string { return "rop4" }

// printVerboseSummary prints the search configuration and a per-binary metadata
// summary (rop3 __init__ verbose block). Best-effort: a binary that fails to
// load is skipped here (the scan reports the real error).
func (a *args) printVerboseSummary(flags int) {
	var kinds []string
	if flags&gadfinder.ROP != 0 {
		kinds = append(kinds, "ROP")
	}
	if flags&gadfinder.JOP != 0 {
		kinds = append(kinds, "JOP")
	}
	if flags&gadfinder.RETF != 0 {
		kinds = append(kinds, "RETF")
	}
	kindStr := "none"
	if len(kinds) > 0 {
		kindStr = joinPlus(kinds)
	}
	depthStr := "auto"
	if a.depth > 0 {
		depthStr = fmt.Sprintf("%d", a.depth)
	}
	debuglog.Info("search: %s, depth %s bytes, 1 job(s)", kindStr, depthStr)

	ropblock := flags&gadfinder.Ropblock != 0
	framed := flags&gadfinder.Unframed == 0
	for i, fn := range a.binary {
		base := ""
		if i < len(a.base) {
			base = a.base[i]
		} else if len(a.base) == 1 {
			base = a.base[0]
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			continue
		}
		bin, err := binfmt.Load(data, base, a.arch, a.raw)
		if err != nil {
			continue
		}
		info := binfmt.Describe(bin, fn, len(data), ropblock, framed)
		for _, line := range output.BinaryInfoLines(info) {
			debuglog.Info("%s", line)
		}
	}
}

func joinPlus(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += "+"
		}
		out += x
	}
	return out
}

func (a *args) toFlags() int {
	f := 0
	if a.all {
		f |= gadfinder.KeepDuplicates
	}
	if a.jop {
		f |= gadfinder.JOP
	}
	if a.rop {
		f |= gadfinder.ROP
	}
	if a.retf {
		f |= gadfinder.RETF
	}
	if a.allowUndet {
		f |= gadfinder.AllowUndeterministic
	}
	if a.allowComplex {
		f |= gadfinder.AllowComplexMem
	}
	if !a.keepCanary {
		f |= gadfinder.AvoidCanary
	}
	if a.retImm {
		f |= gadfinder.AllowRetImm
	}
	if a.regAliases {
		f |= gadfinder.AllowRegAliases
	}
	if a.keepContra {
		f |= gadfinder.KeepContradictory
	}
	if !a.frame {
		f |= gadfinder.Unframed
	}
	if a.allowSeg {
		f |= gadfinder.AllowSegmentOverride
	}
	return f
}

// parse is a minimal hand-rolled parser for rop3's flag set (no external deps).
func parse(argv []string) (*args, error) {
	a := &args{rop: true, frame: true, depth: 0, outputFmt: "text"}
	i := 0
	// collectList consumes following tokens until the next option.
	collectList := func() []string {
		var out []string
		for i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
			i++
			out = append(out, argv[i])
		}
		return out
	}
	next := func(name string) (string, error) {
		if i+1 >= len(argv) {
			return "", fmt.Errorf("%s requires a value", name)
		}
		i++
		return argv[i], nil
	}
	for ; i < len(argv); i++ {
		tok := argv[i]
		switch tok {
		case "-h", "--help":
			fmt.Println(usage())
			os.Exit(0)
		case "-v", "--version":
			a.version = true
		case "--binary":
			a.binary = append(a.binary, collectList()...)
		case "--base":
			a.base = append(a.base, collectList()...)
		case "--badchar":
			a.badchar = append(a.badchar, collectList()...)
		case "--badchar-bytes":
			a.badcharBytes = append(a.badcharBytes, collectList()...)
		case "--arch":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			a.arch = v
		case "--raw":
			a.raw = true
		case "--symbols":
			a.symbols = true
		case "--all":
			a.all = true
		case "--depth":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("--depth: %v", err)
			}
			a.depth = n
		case "--rop":
			a.rop = true
		case "--no-rop":
			a.rop = false
		case "--jop":
			a.jop = true
		case "--no-jop":
			a.jop = false
		case "--retf":
			a.retf = true
		case "--no-retf":
			a.retf = false
		case "--ret-imm":
			a.retImm = true
		case "--no-ret-imm":
			a.retImm = false
		case "--frame":
			a.frame = true
		case "--no-frame":
			a.frame = false
		case "--reg-aliases":
			a.regAliases = true
		case "--allow-undeterministic-gadgets":
			a.allowUndet = true
		case "--allow-complex-memory-ops":
			a.allowComplex = true
		case "--allow-segment-override":
			a.allowSeg = true
		case "--keep-contradictory":
			a.keepContra = true
		case "--keep-canary-address":
			a.keepCanary = true
		case "--cache":
			a.cache = true
		case "--cache-dir":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			a.cacheDir = v
		case "--verbose":
			a.verbose = true
		case "--tuple":
			a.tuple = true
		case "--ropchain":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			a.ropchainFile = v
		case "--exhaustive":
			a.exhaustive = true
		case "--no-exhaustive":
			a.exhaustive = false
		case "--legacy-ropchain":
			a.legacyChain = true
		case "--no-legacy-ropchain":
			a.legacyChain = false
		case "--op":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			a.op = v
		case "--operands":
			a.operands = append(a.operands, collectList()...)
		case "--dst":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			a.dst, a.hasDst = v, true
		case "--src":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			a.src, a.hasSrc = v, true
		case "--output":
			v, err := next(tok)
			if err != nil {
				return nil, err
			}
			if v != "text" && v != "json" && v != "csv" {
				return nil, fmt.Errorf("--output must be text, json or csv")
			}
			a.outputFmt = v
		default:
			return nil, fmt.Errorf("unrecognized argument: %s", tok)
		}
	}
	// Legacy --dst/--src map to positional operands (prefer --operands).
	if a.hasDst || a.hasSrc {
		if len(a.operands) > 0 {
			return nil, fmt.Errorf("--dst/--src cannot be combined with --operands")
		}
		if a.hasDst && a.hasSrc {
			a.operands = []string{a.dst, a.src}
		} else if a.hasDst {
			a.operands = []string{a.dst}
		} else {
			a.operands = []string{a.src}
		}
	}
	return a, nil
}

func usage() string {
	return "usage: rop4 [--binary <file>...] [--rop|--no-rop] [--jop] [--retf] " +
		"[--depth N] [--badchar <hex>...] [--symbols] [--output text|json|csv] [--tuple] ..."
}
