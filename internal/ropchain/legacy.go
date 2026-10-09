package ropchain

import (
	"fmt"
	"sort"

	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/gadget"
)

// legacySlotBase is the base for the fresh internal names --legacy-ropchain's
// free(NAME) rename pass hands out to a post-free reuse of a name. Distinct from
// gadfinder's fresh-slot base so the two name spaces never collide within one
// run (rop3 ropchain._LEGACY_FREE_SLOT_BASE).
const legacySlotBase = 9500000

// rewriteLegacyFrees is the --legacy-ropchain approximation of free (rop3
// RopChain._rewrite_legacy_frees): rewrite the step list so that, from a
// free(NAME) line onward, NAME is a brand-new internal identity, decoupling it
// from its earlier occurrences in Tree's whole-file global intersection.
// free steps are dropped here -- classify_ropchain/Tree never see them.
func rewriteLegacyFrees(steps []gadfinder.ChainStep) []gadfinder.ChainStep {
	epoch := map[string]int{}
	type key struct {
		name  string
		epoch int
	}
	fresh := map[key]string{}
	counter := 0

	resolve := func(value string) string {
		if !IsGenericSlot(value) {
			return value
		}
		e := epoch[value]
		if e == 0 {
			return value
		}
		k := key{value, e}
		if _, ok := fresh[k]; !ok {
			fresh[k] = fmt.Sprintf("REG%d", legacySlotBase+counter)
			counter++
		}
		return fresh[k]
	}

	var out []gadfinder.ChainStep
	for _, step := range steps {
		if step.Free != "" {
			if IsGenericSlot(step.Free) {
				epoch[step.Free]++
			}
			continue
		}
		ns := step // copy
		if step.Operands != nil {
			ops := make([]string, len(step.Operands))
			for i, v := range step.Operands {
				ops[i] = resolve(v)
			}
			ns.Operands = ops
		}
		out = append(out, ns)
	}
	return out
}

// assembleLegacy is the --legacy-ropchain (Tree) assembler for one realization's
// bundle (rop3 RopChain._assemble legacy branch): resolve the generic slots'
// concrete registers with Tree, build the per-combination gadget lists, then DFS
// with side-effect tracking. Appends solutions to *out, stopping at limit (>0).
func (rc *RopChain) assembleLegacy(bundle []gadfinder.ClassifiedStep, pruneEquivalent bool, limit int, out *[][]*gadget.Gadget) {
	steps := make([]stepKeys, len(bundle))
	opsGadgets := make([][]*gadget.Gadget, len(bundle))
	for i, cs := range bundle {
		steps[i] = stepKeys{op1: asStr(cs.Step.Op1), op2: asStr(cs.Step.Op2)}
		opsGadgets[i] = cs.Gadgets
	}

	t := &tree{steps: steps, opsGadgets: opsGadgets, isAbstractReg: rc.gf.Arch().IsValidAbstractReg}
	combinations := t.traverse()

	perComb := buildPerCombGadgets(steps, combinations, opsGadgets, pruneEquivalent)
	constructRopchain(len(steps), combinations, perComb, limit, out)
}

// stepKeys holds a primitive step's op1/op2 keys ("" for a missing/None key).
type stepKeys struct{ op1, op2 string }

// tree resolves the concrete register assignments for the generic register
// slots shared across the (already expanded, 2-operand) chain steps (rop3 Tree).
type tree struct {
	steps         []stepKeys
	opsGadgets    [][]*gadget.Gadget
	isAbstractReg func(string) bool
}

// opPair is one step's generic-generic constraint: the pair keys and the set of
// (slot_op1, slot_op2) register pairs real gadgets exhibit. valid=false marks a
// step that is not generic-generic (no pair constraint, rop3 None entry).
type opPair struct {
	valid    bool
	op1Key   string
	op2Key   string
	pairs    map[[2]string]bool
}

func (t *tree) traverse() []map[string]string {
	order, state, opPairs := t.initialState()
	return t.backtrack(order, state, opPairs)
}

// initialState ports Tree._get_initial_state. order preserves the insertion
// order of state's keys (Python dict order), which fixes the combination
// enumeration order.
func (t *tree) initialState() ([]string, map[string][]string, []opPair) {
	state := map[string][]string{}
	var order []string
	var opPairs []opPair

	for si, item := range t.steps {
		op1Key, op2Key := item.op1, item.op2
		var op1Vals, op2Vals []string

		if IsGenericSlot(op1Key) && IsGenericSlot(op2Key) {
			pairs := map[[2]string]bool{}
			for _, g := range t.opsGadgets[si] {
				if g.SlotOp1 != "" && g.SlotOp2 != "" &&
					t.isAbstractReg(g.SlotOp1) && t.isAbstractReg(g.SlotOp2) {
					pairs[[2]string{g.SlotOp1, g.SlotOp2}] = true
				}
			}
			opPairs = append(opPairs, opPair{valid: true, op1Key: op1Key, op2Key: op2Key, pairs: pairs})
			s1 := map[string]bool{}
			s2 := map[string]bool{}
			for p := range pairs {
				s1[p[0]] = true
				s2[p[1]] = true
			}
			op1Vals = sortedSet(s1)
			op2Vals = sortedSet(s2)
		} else {
			opPairs = append(opPairs, opPair{valid: false})
			if IsGenericSlot(op1Key) {
				s := map[string]bool{}
				for _, g := range t.opsGadgets[si] {
					if g.SlotOp1 != "" && t.isAbstractReg(g.SlotOp1) {
						s[g.SlotOp1] = true
					}
				}
				op1Vals = sortedSet(s)
			}
			if IsGenericSlot(op2Key) {
				s := map[string]bool{}
				for _, g := range t.opsGadgets[si] {
					if g.SlotOp2 != "" && t.isAbstractReg(g.SlotOp2) {
						s[g.SlotOp2] = true
					}
				}
				op2Vals = sortedSet(s)
			}
		}

		for _, kv := range []struct {
			key  string
			vals []string
		}{{op1Key, op1Vals}, {op2Key, op2Vals}} {
			if kv.key == "" || !IsGenericSlot(kv.key) {
				continue
			}
			if existing, ok := state[kv.key]; ok {
				// Intersect, preserving existing order.
				allow := map[string]bool{}
				for _, v := range kv.vals {
					allow[v] = true
				}
				var next []string
				for _, v := range existing {
					if allow[v] {
						next = append(next, v)
					}
				}
				state[kv.key] = next
			} else {
				state[kv.key] = kv.vals
				order = append(order, kv.key)
			}
		}
	}
	return order, state, opPairs
}

// backtrack enumerates the register assignments (rop3 Tree._traverse), keeping
// only those passing _check_pairs.
func (t *tree) backtrack(order []string, state map[string][]string, opPairs []opPair) []map[string]string {
	var results []map[string]string
	current := map[string]string{}
	var rec func(index int)
	rec = func(index int) {
		if index == len(order) {
			cp := make(map[string]string, len(current))
			for k, v := range current {
				cp[k] = v
			}
			results = append(results, cp)
			return
		}
		key := order[index]
		for _, val := range state[key] {
			current[key] = val
			if checkPairs(current, opPairs) {
				rec(index + 1)
			}
			delete(current, key)
		}
	}
	rec(0)
	return results
}

// checkPairs ports Tree._check_pairs: every generic-generic step's chosen
// (op1, op2) pair must be one a real gadget exhibits.
func checkPairs(combo map[string]string, opPairs []opPair) bool {
	for _, e := range opPairs {
		if !e.valid {
			continue
		}
		v1, ok1 := combo[e.op1Key]
		v2, ok2 := combo[e.op2Key]
		if ok1 && ok2 {
			if !e.pairs[[2]string{v1, v2}] {
				return false
			}
		}
	}
	return true
}

// buildPerCombGadgets ports RopChain._build_per_comb_gadgets: for each register
// combination, the per-step gadget list filtered to that combination's concrete
// slot registers, sorted by heuristic, and optionally pruned.
func buildPerCombGadgets(steps []stepKeys, combinations []map[string]string,
	opsGadgets [][]*gadget.Gadget, pruneEquivalent bool) [][][]*gadget.Gadget {

	sortedGadgets := make([][]*gadget.Gadget, len(opsGadgets))
	for i, gl := range opsGadgets {
		gs := append([]*gadget.Gadget(nil), gl...)
		sort.SliceStable(gs, func(a, b int) bool {
			return gadget.HeuristicBasicCount(gs[a]) < gadget.HeuristicBasicCount(gs[b])
		})
		sortedGadgets[i] = gs
	}

	type ckey struct {
		i    int
		r1   string
		h1   bool
		r2   string
		h2   bool
	}
	cache := map[ckey][]*gadget.Gadget{}
	buildStep := func(i int, req1, req2 *string) []*gadget.Gadget {
		k := ckey{i: i}
		if req1 != nil {
			k.r1, k.h1 = *req1, true
		}
		if req2 != nil {
			k.r2, k.h2 = *req2, true
		}
		if c, ok := cache[k]; ok {
			return c
		}
		var filtered []*gadget.Gadget
		for _, g := range sortedGadgets[i] {
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
		cache[k] = filtered
		return filtered
	}

	result := make([][][]*gadget.Gadget, 0, len(combinations))
	for _, comb := range combinations {
		perStep := make([][]*gadget.Gadget, len(steps))
		for i := range steps {
			var req1, req2 *string
			if v, ok := comb[steps[i].op1]; ok {
				req1 = &v
			}
			if v, ok := comb[steps[i].op2]; ok {
				req2 = &v
			}
			perStep[i] = buildStep(i, req1, req2)
		}
		result = append(result, perStep)
	}
	return result
}

// constructRopchain ports RopChain._construct_ropchain: DFS over the
// per-combination gadget lists with dst/src side-effect tracking. Appends
// solutions to *out, stopping at limit (>0).
func constructRopchain(n int, combinations []map[string]string,
	perComb [][][]*gadget.Gadget, limit int, out *[][]*gadget.Gadget) {

	for _, combGadgets := range perComb {
		clobbered := map[string]int{}
		var chain []*gadget.Gadget
		var rec func(index int) bool // returns true to stop (limit reached)
		rec = func(index int) bool {
			if index == n {
				sol := append([]*gadget.Gadget(nil), chain...)
				*out = append(*out, sol)
				return limit > 0 && len(*out) >= limit
			}
			for _, gad := range combGadgets[index] {
				if anyClobbered(gad.Src, clobbered) {
					continue
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
				stop := rec(index + 1)
				chain = chain[:len(chain)-1]
				for reg, old := range refreshed {
					clobbered[reg] = old
				}
				for reg := range gad.SideRegs {
					clobbered[reg]--
				}
				if stop {
					return true
				}
			}
			return false
		}
		if rec(0) {
			return
		}
	}
}

// sortedSet returns the set's members sorted ascending.
func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
