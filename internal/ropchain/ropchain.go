// Package ropchain assembles ROP chains from a ROPLang request, ported from
// rop3/ropchain.py. This is the default order-aware ("sequential") engine plus
// the ROP-chain-file parser and the free(NAME) handling. The Triton symbolic
// validation pass is intentionally omitted (excluded from the Go port). The
// (The legacy rop3 "Tree" engine and its --legacy-ropchain / dst-src comma
// compatibility shims are intentionally not ported; rop4 keeps only the
// order-aware engine.)
package ropchain

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/debuglog"
	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/gadget"
)

// REGEX_OP / COMMENT / REGEX_RAW (rop3 ropchain.py).
var (
	regexOp  = regexp.MustCompile(`^(?P<OP>[a-zA-Z0-9-]+)\((?P<ARGS>[^)]*)\)(?:\s*;.*)?$`)
	comment  = regexp.MustCompile(`^(?:\s*;.*)?$`)
	regexRaw = regexp.MustCompile(`^\s*raw\s*\(`)
)

// RopChain assembles chains using a GadFinder for classification.
type RopChain struct {
	gf *gadfinder.GadFinder
}

// New builds a RopChain over gf.
func New(gf *gadfinder.GadFinder) *RopChain { return &RopChain{gf: gf} }

// IsGenericSlot reports whether key is a generic register-slot name (regN /
// TMP_REG scratch) rather than a concrete register (rop3 _is_generic_slot).
func IsGenericSlot(key string) bool {
	if key == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(key), "reg") ||
		strings.HasPrefix(strings.ToUpper(key), "TMP_REG")
}

// ParseFile reads a ROP-chain file into steps (rop3 _parse_ropfile).
func ParseFile(path string) ([]gadfinder.ChainStep, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBytes(data, path)
}

// ParseBytes parses ROPLang chain text into steps. source labels the input in
// per-line error messages (a file path, or a bundled-chain name).
func ParseBytes(data []byte, source string) ([]gadfinder.ChainStep, error) {
	var steps []gadfinder.ChainStep
	for i, line := range strings.Split(string(data), "\n") {
		lineNo := i + 1
		if regexRaw.MatchString(line) {
			step, err := parseRawLine(line)
			if err != nil {
				return nil, fmt.Errorf("%s: line %d: %s: %w", source, lineNo, strings.TrimSpace(line), err)
			}
			steps = append(steps, step)
			continue
		}
		if m := regexOp.FindStringSubmatch(line); m != nil {
			opName := m[1]
			args := strings.TrimSpace(m[2])
			var raw []string
			if args != "" {
				for _, a := range strings.Split(args, ",") {
					raw = append(raw, strings.TrimSpace(a))
				}
			}
			if opName == "free" {
				fe, err := parseFreeLine(m[0], raw)
				if err != nil {
					return nil, fmt.Errorf("%s: line %d: %s: %w", source, lineNo, line, err)
				}
				steps = append(steps, fe)
				continue
			}
			steps = append(steps, gadfinder.ChainStep{
				Data: m[0], Op: opName, Operands: splitOperands(raw),
			})
		} else if comment.MatchString(line) {
			// comment or blank
		} else {
			return nil, fmt.Errorf("%s: line %d: %s: unable to parse operation", source, lineNo, line)
		}
	}
	return steps, nil
}

// splitOperands drops empty tokens from a comma-split operand list (operands
// are purely positional: op1, op2, ...).
func splitOperands(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func parseFreeLine(data string, raw []string) (gadfinder.ChainStep, error) {
	if len(raw) != 1 || raw[0] == "" {
		return gadfinder.ChainStep{}, fmt.Errorf("free(...) takes exactly one register-slot name, e.g. free(REG1)")
	}
	return gadfinder.ChainStep{Data: data, Op: "free", Free: raw[0]}, nil
}

// checkFreeUsage emits diagnostics for dubious free() usage (rop3 _check_free_usage).
func checkFreeUsage(steps []gadfinder.ChainStep) {
	everSeen := map[string]bool{}
	pending := map[string]bool{}
	for _, step := range steps {
		if step.Free != "" {
			f := step.Free
			switch {
			case !IsGenericSlot(f):
				debuglog.Warning("free(%s): only a generic register-slot name (regN) can be freed; ignoring", f)
			case !everSeen[f]:
				debuglog.Warning("free(%s): %s was never used before this point in the file; ignoring", f, f)
			case pending[f]:
				debuglog.Warning("free(%s): %s was already freed with no intervening use since; ignoring the repeated free", f, f)
			default:
				pending[f] = true
			}
			continue
		}
		for _, v := range step.Operands {
			if IsGenericSlot(v) {
				everSeen[v] = true
				delete(pending, v)
			}
		}
	}
}

// RawContext carries what a raw(...) chain step's direct scan needs: the target
// binaries and the scan options (rop3 search's binaries/base/badchars/arch/raw
// parameters). nil (or empty Binaries) means a raw step degrades to matching
// only against the given gadgets, as rop3 does without binaries.
type RawContext struct {
	Binaries []string
	Opt      gadfinder.FindOpts
}

// Search parses nothing; it takes already-parsed steps, classifies, and
// assembles. limit>0 stops after that many solutions (1 for non-exhaustive
// text); limit==0 yields all. Mirrors rop3 RopChain.search (default engine).
// raw supplies the target binaries/options for resolving raw(...) steps (nil
// when there are none).
func (rc *RopChain) Search(gadgets []*gadget.Gadget, steps []gadfinder.ChainStep, pruneEquivalent bool, limit int, raw *RawContext) ([][]*gadget.Gadget, error) {
	checkFreeUsage(steps)
	if err := rc.resolveRawGadgets(steps, raw); err != nil {
		return nil, err
	}

	realizations, err := rc.gf.ClassifyRopchain(gadgets, steps)
	if err != nil {
		return nil, err
	}
	var solutions [][]*gadget.Gadget
	for _, r := range realizations {
		rc.assembleSequential(r.Bundle, pruneEquivalent, r.FreeEvents, limit, &solutions)
		if limit > 0 && len(solutions) >= limit {
			return solutions[:limit], nil
		}
	}
	if len(solutions) == 0 {
		return nil, &gadfinder.RopChainNotFound{}
	}
	return solutions, nil
}

// SearchFromGadgets parses the chain request then searches (rop3
// search_from_gadgets). ropfile is either a path to a ROPLang file or, when no
// such file exists, the name of a bundled chain (e.g. "turing"), resolved to the
// embedded variant for the target binary's detected architecture. raw supplies
// the target binaries/options for raw(...) steps (nil disables).
func (rc *RopChain) SearchFromGadgets(gadgets []*gadget.Gadget, ropfile string, limit int, raw *RawContext) ([][]*gadget.Gadget, error) {
	steps, err := rc.parseRopRequest(ropfile)
	if err != nil {
		return nil, err
	}
	return rc.Search(gadgets, steps, true, limit, raw)
}

// parseRopRequest resolves ropfile to chain steps. An existing file on disk is
// always loaded as-is; otherwise ropfile is treated as a bundled-chain name and
// matched against the embedded chains for the target's detected architecture.
func (rc *RopChain) parseRopRequest(ropfile string) ([]gadfinder.ChainStep, error) {
	if _, err := os.Stat(ropfile); err == nil {
		return ParseFile(ropfile)
	}
	data, name, err := rc.lookupEmbeddedChain(ropfile)
	if err != nil {
		return nil, err
	}
	return ParseBytes(data, name)
}

// lookupEmbeddedChain returns the bundled chain for the given name and the
// target's detected architecture, or an error naming what is available.
func (rc *RopChain) lookupEmbeddedChain(name string) (data []byte, label string, err error) {
	token := archToken(rc.gf.Arch())
	if token != "" {
		file := "chains/" + name + "_" + token + ".txt"
		if b, rerr := embeddedChains.ReadFile(file); rerr == nil {
			return b, "<bundled chain " + name + "_" + token + ">", nil
		}
	}
	avail := listEmbeddedChains()
	if arches, ok := avail[name]; ok {
		return nil, "", fmt.Errorf("no bundled ROP chain %q for arch %q (that chain is available for: %s)",
			name, token, strings.Join(arches, ", "))
	}
	names := make([]string, 0, len(avail))
	for n := range avail {
		names = append(names, n)
	}
	sort.Strings(names)
	return nil, "", fmt.Errorf("%q is neither a readable file nor a bundled ROP chain (bundled chains: %s)",
		name, strings.Join(names, ", "))
}

// archToken maps a detected architecture to the suffix used by the embedded
// chain filenames (chains/<name>_<token>.txt). It returns "" for an arch that
// has no bundled chains.
func archToken(a arch.Arch) string {
	switch a.(type) {
	case *arch.X64:
		return "amd64"
	case *arch.X86:
		return "x86"
	case *arch.AArch64:
		return "aarch64"
	case *arch.RISCV:
		return "riscv"
	default:
		return ""
	}
}

// listEmbeddedChains groups the embedded chains by base name, mapping each to
// its sorted list of available architecture tokens.
func listEmbeddedChains() map[string][]string {
	out := map[string][]string{}
	entries, err := fs.ReadDir(embeddedChains, "chains")
	if err != nil {
		return out
	}
	for _, e := range entries {
		base := strings.TrimSuffix(e.Name(), path.Ext(e.Name()))
		i := strings.LastIndex(base, "_")
		if i <= 0 {
			continue
		}
		name, token := base[:i], base[i+1:]
		out[name] = append(out[name], token)
	}
	for n := range out {
		sort.Strings(out[n])
	}
	return out
}

// resolveRawGadgets fills in each raw(...) step's inline defn.LiteralGadgets via
// GadFinder.FindRawGadgets (rop3 RopChain._resolve_raw_gadgets). A step whose
// LiteralGadgets is already resolved is not rescanned.
func (rc *RopChain) resolveRawGadgets(steps []gadfinder.ChainStep, raw *RawContext) error {
	if raw == nil || len(raw.Binaries) == 0 {
		return nil
	}
	for _, step := range steps {
		defn := step.Defn
		if defn == nil || defn.LiteralGadgets != nil {
			continue
		}
		gs, err := rc.gf.FindRawGadgets(raw.Binaries, defn, raw.Opt)
		if err != nil {
			return err
		}
		if gs == nil {
			gs = []*gadget.Gadget{} // mark resolved (rop3 sets [] on no hit)
		}
		defn.LiteralGadgets = gs
	}
	return nil
}

// prune removes gadgets subsumed by an earlier kept gadget (rop3 _prune).
func prune(list []*gadget.Gadget) []*gadget.Gadget {
	var ret []*gadget.Gadget
	for _, g := range list {
		subsumed := false
		for _, kept := range ret {
			if kept.Subsumes(g) {
				subsumed = true
				break
			}
		}
		if !subsumed {
			ret = append(ret, g)
		}
	}
	return ret
}

// assembleSequential is the order-aware backtracking DFS (rop3
// _assemble_sequential). It appends solutions to *out, stopping at limit (>0).
func (rc *RopChain) assembleSequential(bundle []gadfinder.ClassifiedStep, pruneEquivalent bool, freeEvents []gadfinder.FreeEvent, limit int, out *[][]*gadget.Gadget) {
	n := len(bundle)
	steps := make([]operationStep, n)
	sortedGadgets := make([][]*gadget.Gadget, n)
	for i, cs := range bundle {
		steps[i] = operationStep{op1: asStr(cs.Step.Op1), op2: asStr(cs.Step.Op2)}
		gs := append([]*gadget.Gadget(nil), cs.Gadgets...)
		sort.SliceStable(gs, func(a, b int) bool {
			return gadget.HeuristicBasicCount(gs[a]) < gadget.HeuristicBasicCount(gs[b])
		})
		sortedGadgets[i] = gs
	}

	freesAt := map[int][]string{}
	for _, fe := range freeEvents {
		freesAt[fe.Boundary] = append(freesAt[fe.Boundary], fe.Name)
	}

	type candKey struct {
		index    int
		req1     string
		req2     string
		has1     bool
		has2     bool
	}
	cache := map[candKey][]*gadget.Gadget{}
	candidates := func(index int, req1, req2 *string) []*gadget.Gadget {
		key := candKey{index: index}
		if req1 != nil {
			key.req1, key.has1 = *req1, true
		}
		if req2 != nil {
			key.req2, key.has2 = *req2, true
		}
		if c, ok := cache[key]; ok {
			return c
		}
		var filtered []*gadget.Gadget
		for _, g := range sortedGadgets[index] {
			if req1 != nil && g.SlotOp1 != *req1 {
				continue
			}
			if req2 != nil && g.SlotOp2 != *req2 {
				continue
			}
			filtered = append(filtered, g)
		}
		if pruneEquivalent {
			filtered = prune(filtered)
		}
		cache[key] = filtered
		return filtered
	}

	requirement := func(key string, live map[string]string) *string {
		if !IsGenericSlot(key) {
			return nil
		}
		if v, ok := live[key]; ok {
			return &v
		}
		return nil
	}

	clobbered := map[string]int{}
	live := map[string]string{}
	var chain []*gadget.Gadget

	var backtrack func(index int) bool // returns true to stop (limit reached)
	backtrack = func(index int) bool {
		freedHere := freesAt[index]
		saved := map[string]string{}
		for _, name := range freedHere {
			if v, ok := live[name]; ok {
				saved[name] = v
				delete(live, name)
			}
		}
		restore := func() {
			for name, v := range saved {
				live[name] = v
			}
		}

		if index == n {
			sol := append([]*gadget.Gadget(nil), chain...)
			*out = append(*out, sol)
			restore()
			return limit > 0 && len(*out) >= limit
		}

		st := steps[index]
		req1 := requirement(st.op1, live)
		req2 := requirement(st.op2, live)
		for _, gad := range candidates(index, req1, req2) {
			if anyClobbered(gad.Src, clobbered) {
				continue
			}
			newlyBound, ok := slotBindings(st.op1, st.op2, gad, live)
			if !ok {
				continue
			}
			for k, v := range newlyBound {
				live[k] = v
			}
			for reg := range gad.SideRegs {
				clobbered[reg]++
			}
			refreshed := map[string]int{}
			for reg := range gad.Dst {
				if gad.WritesReg(reg) {
					refreshed[reg] = clobbered[reg]
					clobbered[reg] = 0
				}
			}
			chain = append(chain, gad)
			stop := backtrack(index + 1)
			chain = chain[:len(chain)-1]
			for reg, old := range refreshed {
				clobbered[reg] = old
			}
			for reg := range gad.SideRegs {
				clobbered[reg]--
			}
			for k := range newlyBound {
				delete(live, k)
			}
			if stop {
				restore()
				return true
			}
		}
		restore()
		return false
	}
	backtrack(0)
}

type operationStep struct{ op1, op2 string }

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func anyClobbered(src map[string]bool, clobbered map[string]int) bool {
	for reg := range src {
		if clobbered[reg] > 0 {
			return true
		}
	}
	return false
}

// slotBindings ports RopChain._slot_bindings.
func slotBindings(op1Key, op2Key string, gad *gadget.Gadget, live map[string]string) (map[string]string, bool) {
	proposed := map[string]string{}
	pairs := []struct {
		k string
		v string
	}{{op1Key, gad.SlotOp1}, {op2Key, gad.SlotOp2}}
	for _, p := range pairs {
		if !IsGenericSlot(p.k) {
			continue
		}
		if _, ok := live[p.k]; ok {
			continue
		}
		if p.v == "" {
			return nil, false // slot bound to a non-register
		}
		if ex, ok := proposed[p.k]; ok {
			if ex != p.v {
				return nil, false // same slot, two registers
			}
			continue
		}
		proposed[p.k] = p.v
	}
	if len(proposed) == 0 {
		return proposed, true
	}
	occupied := map[string]bool{}
	for name, r := range live {
		if IsGenericSlot(name) {
			occupied[r] = true
		}
	}
	seen := map[string]bool{}
	for _, v := range proposed {
		if occupied[v] || seen[v] {
			return nil, false // distinct slots collapse onto one register
		}
		seen[v] = true
	}
	return proposed, true
}
