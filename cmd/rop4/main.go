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

	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/output"
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
	version      bool
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
	gf := gadfinder.New(a.depth, flags, 1)
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
	if err := output.Gadgets(os.Stdout, gadgets, outFmt); err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %s\n", toolName(), err)
		os.Exit(1)
	}
}

func toolName() string { return "rop4" }

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
		case "--tuple":
			a.tuple = true
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
	return a, nil
}

func usage() string {
	return "usage: rop4 [--binary <file>...] [--rop|--no-rop] [--jop] [--retf] " +
		"[--depth N] [--badchar <hex>...] [--symbols] [--output text|json|csv] [--tuple] ..."
}
