package gadfinder

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/operation"
)

// Slot-name bases (rop3 gadfinder._FRESH_SLOT_BASE / _TEMP_SLOT_BASE).
const (
	freshSlotBase = 9000000
	tempSlotBase  = 9900000
)

var tempSlotRE = regexp.MustCompile(`^TMP_REG\d*$`)

func isTempSlot(v any) bool {
	s, ok := v.(string)
	return ok && tempSlotRE.MatchString(s)
}

// ChainStep is one parsed line of a ROP-chain request: an operation with
// positional operands, a free(NAME) directive (Free set), or an explicit raw
// gadget (Defn set). Mirrors rop3's parsed step dicts.
type ChainStep struct {
	Data     string
	Op       string
	Operands []string
	Free     string
	Defn     *operation.OperationDef // inline (raw) gadget definition, if any
}

// ClassifiedStep pairs a primitive step with the gadgets realizing it.
type ClassifiedStep struct {
	Step    operation.Step
	Gadgets []*gadget.Gadget
}

// FreeEvent marks that generic slot Name is released after Boundary primitives.
type FreeEvent struct {
	Boundary int
	Name     string
}

// Realization is one candidate expansion of the whole chain request.
type Realization struct {
	Bundle     []ClassifiedStep
	FreeEvents []FreeEvent
}

type counter struct{ n int }

func (c *counter) next() int { v := c.n; c.n++; return v }

// ClassifyRopchain resolves a parsed ROP-chain request into the gadgets that
// realize it (rop3 GadFinder.classify_ropchain). Returns one Realization per
// compound-operation alternative; realizations with an unmatchable primitive
// are dropped.
func (gf *GadFinder) ClassifyRopchain(gadgets []*gadget.Gadget, steps []ChainStep, legacy bool) ([]Realization, error) {
	p, err := gf.parser()
	if err != nil {
		return nil, err
	}
	resolve := func(name string) (*operation.OperationDef, error) { return p.GetOp(name) }

	fresh := &counter{}
	tempFresh := &counter{}

	type alt struct {
		chain []operation.Step
		temps []string
	}
	var perStep [][]alt
	freeNames := make([]string, 0, len(steps))

	for _, step := range steps {
		if step.Free != "" {
			perStep = append(perStep, []alt{{chain: nil, temps: nil}})
			freeNames = append(freeNames, step.Free)
			continue
		}
		defn, err := gf.stepDefn(step, p)
		if err != nil {
			return nil, err
		}
		binding := gf.bindStep(step, fresh, defn)
		alternatives, err := operation.Realize(defn, binding, resolve)
		if err != nil {
			return nil, &RopChainNotFound{Msg: err.Error()}
		}
		if len(alternatives) == 0 {
			data := step.Data
			if data == "" {
				data = step.Op
			}
			return nil, &RopChainNotFound{Msg: fmt.Sprintf("%s: no realization for operation", data)}
		}
		alts := make([]alt, 0, len(alternatives))
		for _, chain := range alternatives {
			c, temps := gf.prepareTempSlots(chain, legacy, tempFresh)
			alts = append(alts, alt{chain: c, temps: temps})
		}
		perStep = append(perStep, alts)
		freeNames = append(freeNames, "")
	}

	var realizations []Realization
	indices := make([]int, len(perStep))
	for {
		// Build this combination.
		var primitives []operation.Step
		var freeEvents []FreeEvent
		for si := range perStep {
			a := perStep[si][indices[si]]
			if freeNames[si] != "" {
				freeEvents = append(freeEvents, FreeEvent{Boundary: len(primitives), Name: freeNames[si]})
				continue
			}
			primitives = append(primitives, a.chain...)
			for _, t := range a.temps {
				freeEvents = append(freeEvents, FreeEvent{Boundary: len(primitives), Name: t})
			}
		}
		if bundle := gf.matchPrimitives(gadgets, primitives); bundle != nil {
			realizations = append(realizations, Realization{Bundle: bundle, FreeEvents: freeEvents})
		}
		// Advance the odometer over perStep alternatives.
		k := len(perStep) - 1
		for ; k >= 0; k-- {
			indices[k]++
			if indices[k] < len(perStep[k]) {
				break
			}
			indices[k] = 0
		}
		if k < 0 {
			break
		}
	}
	return realizations, nil
}

func (gf *GadFinder) stepDefn(step ChainStep, p interface {
	GetOp(string) (*operation.OperationDef, error)
}) (*operation.OperationDef, error) {
	if step.Defn != nil {
		return step.Defn, nil
	}
	return p.GetOp(step.Op)
}

// bindStep resolves a step's operands to concrete regs or fresh generic slots.
func (gf *GadFinder) bindStep(step ChainStep, fresh *counter, defn *operation.OperationDef) map[string]any {
	binding := map[string]any{}
	for i := 0; i < defn.Operands; i++ {
		var value any
		if i < len(step.Operands) && step.Operands[i] != "" {
			value = step.Operands[i]
		} else {
			value = fmt.Sprintf("REG%d", freshSlotBase+fresh.next())
		}
		binding[fmt.Sprintf("op%d", i+1)] = value
	}
	return binding
}

// prepareTempSlots mirrors rop3._prepare_temp_slots.
func (gf *GadFinder) prepareTempSlots(chain []operation.Step, legacy bool, tempFresh *counter) ([]operation.Step, []string) {
	var temps []string
	seen := map[string]bool{}
	for _, prim := range chain {
		for _, v := range []any{prim.Op1, prim.Op2} {
			if isTempSlot(v) {
				s := v.(string)
				if !seen[s] {
					seen[s] = true
					temps = append(temps, s)
				}
			}
		}
	}
	if len(temps) == 0 {
		return chain, nil
	}
	if !legacy {
		return chain, temps
	}
	rename := map[string]string{}
	for _, t := range temps {
		rename[t] = fmt.Sprintf("REG%d", tempSlotBase+tempFresh.next())
	}
	renamed := make([]operation.Step, len(chain))
	for i, prim := range chain {
		if s, ok := prim.Op1.(string); ok {
			if r, ok := rename[s]; ok {
				prim.Op1 = r
			}
		}
		if s, ok := prim.Op2.(string); ok {
			if r, ok := rename[s]; ok {
				prim.Op2 = r
			}
		}
		renamed[i] = prim
	}
	return renamed, nil
}

// matchPrimitives matches each primitive against gadgets (rop3._match_primitives).
func (gf *GadFinder) matchPrimitives(gadgets []*gadget.Gadget, primitives []operation.Step) []ClassifiedStep {
	bundle := make([]ClassifiedStep, 0, len(primitives))
	for _, prim := range primitives {
		operands := []any{gf.resolveOperandAny(prim.Op1), gf.resolveOperandAny(prim.Op2)}
		// A raw(...) primitive may carry its own literal_gadgets (candidates
		// found by FindRawGadgets's direct scan). They join the pool for THIS
		// primitive only, never merged into the shared gadget pool: a raw gadget
		// with no terminator returns control nowhere, so leaking one into the
		// shared pool could let an unrelated step pick it (rop3 _match_primitives).
		pool := gadgets
		if prim.Defn != nil && len(prim.Defn.LiteralGadgets) > 0 {
			pool = append(append([]*gadget.Gadget(nil), gadgets...), prim.Defn.LiteralGadgets...)
		}
		gads, err := operation.MatchGadgets(gf.arch, gf.has(AllowRegAliases), prim.Defn, operands, pool, true)
		if err != nil || len(gads) == 0 {
			return nil
		}
		bundle = append(bundle, ClassifiedStep{Step: prim, Gadgets: gads})
	}
	return bundle
}

// resolveOperandAny is resolveOperand over an any (string or nil).
func (gf *GadFinder) resolveOperandAny(val any) any {
	s, ok := val.(string)
	if !ok || s == "" {
		return nil
	}
	if aliased := gf.resolveRegAlias(s); aliased != s {
		return aliased
	}
	if strings.HasPrefix(strings.ToLower(s), "reg") || strings.HasPrefix(strings.ToUpper(s), "TMP_REG") {
		return nil
	}
	return s
}
