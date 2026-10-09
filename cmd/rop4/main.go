// Command rop4 is the CLI entry point. Argument parsing uses the standard
// library flag package. Boolean options default sensibly and are disabled with
// the idiomatic -flag=false form (there are no --no-xxx aliases). List options
// (-binary, -base, -badchar, -badchar-bytes, -operands) may be repeated or
// given comma-separated.
//
// The rop3 backward-compatibility options (--dst/--src, --legacy-ropchain and
// its Tree engine, the legacy dst/src comma markers) are intentionally not
// provided; operands are purely positional and the order-aware chain engine is
// the only one.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/debuglog"
	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/output"
	"github.com/reverseame/rop4/internal/repl"
	"github.com/reverseame/rop4/internal/ropchain"
)

// stringSlice is a repeatable, comma-splitting flag.Value.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

type args struct {
	binary       stringSlice
	base         stringSlice
	badchar      stringSlice
	badcharBytes stringSlice
	operands     stringSlice
	arch         string
	raw          bool
	symbols      bool
	all          bool
	depth        int
	jobs         int
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
	ropblock     bool
	outputFmt    string
	tuple        bool
	interactive  bool
	cache        bool
	cacheDir     string
	verbose      bool
	version      bool
	op           string
	ropchainFile string
	exhaustive   bool
}

func parse(argv []string) (*args, error) {
	a := &args{}
	fs := flag.NewFlagSet("rop4", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.Var(&a.binary, "binary", "binary file to analyze (repeatable or comma-separated)")
	fs.Var(&a.base, "base", "base address to relocate a binary (one per binary)")
	fs.Var(&a.badchar, "badchar", "hex byte to avoid in gadget addresses (repeatable)")
	fs.Var(&a.badcharBytes, "badchar-bytes", "hex byte to avoid in gadget opcode bytes (repeatable)")
	fs.Var(&a.operands, "operands", "operation operands, positional (e.g. -operands rdi,rax)")
	fs.StringVar(&a.arch, "arch", "", "architecture slice (fat Mach-O) or raw-dump arch")
	fs.BoolVar(&a.raw, "raw", false, "treat the input as a formatless raw code dump (needs -arch)")
	fs.BoolVar(&a.symbols, "symbols", false, "annotate gadgets with the nearest symbol")
	fs.BoolVar(&a.all, "all", false, "keep the same gadget at different addresses")
	fs.IntVar(&a.depth, "depth", 0, "maximum gadget length in bytes (0 = architecture default)")
	fs.IntVar(&a.jobs, "jobs", runtime.NumCPU(), "worker goroutines for the scan")
	fs.BoolVar(&a.rop, "rop", true, "search for ROP gadgets")
	fs.BoolVar(&a.jop, "jop", false, "search for JOP gadgets")
	fs.BoolVar(&a.retf, "retf", false, "search for RETF gadgets")
	fs.BoolVar(&a.retImm, "ret-imm", false, "include gadgets ending in ret <imm> / retf <imm>")
	fs.BoolVar(&a.frame, "frame", true, "framed gadget search (AArch64/RISC-V)")
	fs.BoolVar(&a.ropblock, "ropblock", false, "abstract-gadget search (single-threaded)")
	fs.BoolVar(&a.regAliases, "reg-aliases", false, "allow sub-register aliases to match a full register")
	fs.BoolVar(&a.allowUndet, "allow-undeterministic-gadgets", false, "allow intermediate conditional branches")
	fs.BoolVar(&a.allowComplex, "allow-complex-memory-ops", false, "allow complex first-instruction memory operands")
	fs.BoolVar(&a.allowSeg, "allow-segment-override", false, "allow a first-instruction segment override")
	fs.BoolVar(&a.keepContra, "keep-contradictory", false, "keep contradictory operation gadgets")
	fs.BoolVar(&a.keepCanary, "keep-canary-address", false, "do not prefer canary-free duplicate addresses")
	fs.StringVar(&a.outputFmt, "output", "text", "output format: text, json or csv")
	fs.BoolVar(&a.tuple, "tuple", false, "print each gadget as a tuple (overrides -output text)")
	fs.BoolVar(&a.interactive, "interactive", false, "scan once and drop into a REPL")
	fs.BoolVar(&a.cache, "cache", false, "cache discovered gadgets on disk")
	fs.StringVar(&a.cacheDir, "cache-dir", "", "gadget cache directory")
	fs.BoolVar(&a.verbose, "verbose", false, "print scan configuration and per-binary metadata")
	fs.BoolVar(&a.version, "version", false, "print version and exit")
	fs.StringVar(&a.op, "op", "", "search for a high-level operation")
	fs.StringVar(&a.ropchainFile, "ropchain", "", "assemble a ROP chain from a file")
	fs.BoolVar(&a.exhaustive, "exhaustive", false, "emit every ROP-chain solution")

	if err := fs.Parse(argv); err != nil {
		return nil, err
	}
	switch a.outputFmt {
	case "text", "json", "csv":
	default:
		return nil, fmt.Errorf("-output must be text, json or csv")
	}
	if a.jobs < 1 {
		return nil, fmt.Errorf("-jobs must be a positive integer")
	}
	return a, nil
}

func main() {
	a, err := parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "%s: error: %s\n", toolName(), err)
		os.Exit(2)
	}
	if a.version {
		fmt.Printf("%s v%s\n", toolName(), output.Version)
		return
	}
	if len(a.binary) == 0 {
		fmt.Fprintf(os.Stderr, "%s: error: -binary is required\n", toolName())
		os.Exit(2)
	}

	flags := a.toFlags()
	if a.verbose {
		debuglog.SetVerbose(true)
		a.printVerboseSummary(flags)
	}
	gf := gadfinder.New(a.depth, flags, a.jobs)
	if a.cache {
		gf.SetCache(a.cacheDir)
	}
	findOpts := gadfinder.FindOpts{
		Bases: a.base, Badchars: a.badchar, BadcharBytes: a.badcharBytes,
		ArchName: a.arch, Symbols: a.symbols, Raw: a.raw,
	}
	gadgets, err := gf.Find(a.binary, findOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %s\n", toolName(), err)
		os.Exit(1)
	}

	if a.interactive {
		repl.New(gf, gadgets, a.binary, findOpts, os.Stdin, os.Stdout).Run()
		return
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
		limit := 0
		if !a.exhaustive && (outFmt == "text" || outFmt == "tuple") {
			limit = 1 // non-exhaustive text/tuple consumes only the first chain
		}
		rawCtx := &ropchain.RawContext{Binaries: a.binary, Opt: gadfinder.FindOpts{
			Bases: a.base, Badchars: a.badchar, BadcharBytes: a.badcharBytes,
			ArchName: a.arch, Raw: a.raw,
		}}
		chains, err := ropchain.New(gf).SearchFromGadgets(gadgets, a.ropchainFile, limit, rawCtx)
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
		// A compound operation expands into ROP chains.
		if errors.Is(err, gadfinder.ErrCompoundUnsupported) {
			step := gadfinder.ChainStep{Op: a.op, Operands: a.operands,
				Data: a.op + "(" + strings.Join(a.operands, ", ") + ")"}
			chains, cerr := ropchain.New(gf).Search(gadgets, []gadfinder.ChainStep{step}, false, 0, nil)
			if cerr != nil {
				var rcnf *gadfinder.RopChainNotFound
				if !errors.As(cerr, &rcnf) {
					fail(cerr)
				}
				chains = nil
			}
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

func toolName() string { return "rop4" }

func (a *args) toFlags() int {
	f := 0
	set := func(cond bool, flag int) {
		if cond {
			f |= flag
		}
	}
	set(a.all, gadfinder.KeepDuplicates)
	set(a.jop, gadfinder.JOP)
	set(a.rop, gadfinder.ROP)
	set(a.retf, gadfinder.RETF)
	set(a.allowUndet, gadfinder.AllowUndeterministic)
	set(a.allowComplex, gadfinder.AllowComplexMem)
	set(!a.keepCanary, gadfinder.AvoidCanary)
	set(a.retImm, gadfinder.AllowRetImm)
	set(a.regAliases, gadfinder.AllowRegAliases)
	set(a.keepContra, gadfinder.KeepContradictory)
	set(!a.frame, gadfinder.Unframed)
	set(a.allowSeg, gadfinder.AllowSegmentOverride)
	set(a.ropblock, gadfinder.Ropblock)
	return f
}

// printVerboseSummary prints the search configuration and per-binary metadata.
func (a *args) printVerboseSummary(flags int) {
	var kinds []string
	for _, k := range []struct {
		on   bool
		name string
	}{{flags&gadfinder.ROP != 0, "ROP"}, {flags&gadfinder.JOP != 0, "JOP"}, {flags&gadfinder.RETF != 0, "RETF"}} {
		if k.on {
			kinds = append(kinds, k.name)
		}
	}
	kindStr := "none"
	if len(kinds) > 0 {
		kindStr = strings.Join(kinds, "+")
	}
	depthStr := "auto"
	if a.depth > 0 {
		depthStr = fmt.Sprintf("%d", a.depth)
	}
	debuglog.Info("search: %s, depth %s bytes, %d job(s)", kindStr, depthStr, a.jobs)

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
