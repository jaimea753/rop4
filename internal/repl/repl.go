// Package repl is rop4's interactive mode (ported from rop3/interactive.py):
// scan the binary once, then explore gadgets/operations/chains from a prompt.
package repl

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/ropchain"
)

// Shell is the REPL state: the finder, the once-scanned gadgets, and the names.
type Shell struct {
	gf       *gadfinder.GadFinder
	gadgets  []*gadget.Gadget
	binaries []string
	opt      gadfinder.FindOpts
	in       io.Reader
	out      io.Writer
}

// New builds a shell over an already-scanned gadget list. opt carries the scan
// options used so a chain file's raw(...) steps can be resolved against the
// binaries.
func New(gf *gadfinder.GadFinder, gadgets []*gadget.Gadget, binaries []string, opt gadfinder.FindOpts, in io.Reader, out io.Writer) *Shell {
	return &Shell{gf: gf, gadgets: gadgets, binaries: binaries, opt: opt, in: in, out: out}
}

const intro = `rop4 interactive mode. The binary is scanned once; type "help" or "?" for commands.`

// Run reads commands until EOF or quit.
func (s *Shell) Run() {
	fmt.Fprintln(s.out, intro)
	fmt.Fprintf(s.out, "Loaded %d gadgets from %s\n", len(s.gadgets), strings.Join(s.binaries, ", "))
	sc := bufio.NewScanner(s.in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for {
		fmt.Fprint(s.out, "rop4> ")
		if !sc.Scan() {
			fmt.Fprintln(s.out)
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		cmd, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		switch cmd {
		case "gadgets", "search":
			s.doGadgets(rest)
		case "count":
			fmt.Fprintln(s.out, len(s.gadgets))
		case "op":
			s.doOp(rest)
		case "chain":
			s.doChain(rest)
		case "help", "?":
			s.doHelp()
		case "quit", "exit", "EOF":
			return
		default:
			fmt.Fprintf(s.out, "unknown command: %s (type help)\n", cmd)
		}
	}
}

func (s *Shell) doGadgets(needle string) {
	shown := 0
	for _, g := range s.gadgets {
		if needle == "" || strings.Contains(g.String(), needle) {
			fmt.Fprintln(s.out, g.String())
			shown++
		}
	}
	fmt.Fprintf(s.out, "(%d gadgets)\n", shown)
}

func (s *Shell) doOp(arg string) {
	parts := strings.Fields(arg)
	if len(parts) == 0 {
		fmt.Fprintln(s.out, "usage: op <name> [operands...]")
		return
	}
	op := parts[0]
	operands := parts[1:]
	result, err := s.gf.FindOp(s.gadgets, op, operands)
	if err == nil {
		for _, g := range result {
			fmt.Fprintln(s.out, g.String())
		}
		return
	}
	if errors.Is(err, gadfinder.ErrCompoundUnsupported) {
		step := gadfinder.ChainStep{Op: op, Operands: operands, Data: op + "(" + strings.Join(operands, ", ") + ")"}
		chains, cerr := ropchain.New(s.gf).Search(s.gadgets, []gadfinder.ChainStep{step}, false, false, 0, nil)
		if cerr != nil {
			var rcnf *gadfinder.RopChainNotFound
			if !errors.As(cerr, &rcnf) {
				fmt.Fprintln(s.out, cerr.Error())
			}
			return
		}
		for _, chain := range chains {
			for _, g := range chain {
				fmt.Fprintln(s.out, g.String())
			}
		}
		return
	}
	fmt.Fprintln(s.out, err.Error())
}

func (s *Shell) doChain(arg string) {
	if arg == "" {
		fmt.Fprintln(s.out, "usage: chain <file>")
		return
	}
	chains, err := ropchain.New(s.gf).SearchFromGadgets(s.gadgets, arg, false, 1, &ropchain.RawContext{Binaries: s.binaries, Opt: s.opt})
	if err != nil {
		var rcnf *gadfinder.RopChainNotFound
		if errors.As(err, &rcnf) {
			fmt.Fprintf(s.out, "No ROP chain found: %s\n", rcnf.Error())
			return
		}
		fmt.Fprintln(s.out, err.Error())
		return
	}
	if len(chains) == 0 {
		fmt.Fprintln(s.out, "No ROP chain found")
		return
	}
	for _, g := range chains[0] {
		fmt.Fprintln(s.out, g.String())
	}
}

func (s *Shell) doHelp() {
	fmt.Fprintln(s.out, "commands: gadgets [substr] | search [substr] | count | op <name> [operands...] | chain <file> | help | quit")
}
