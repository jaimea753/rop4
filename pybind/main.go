// Command pybind builds rop4 as a C shared library (-buildmode=c-shared) with a
// single JSON-in / JSON-out entry point, Rop4Call, so other languages (Python)
// can drive the engine. The Python wrapper is in ../python/rop4.py.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/gadfinder"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/output"
	"github.com/reverseame/rop4/internal/ropchain"
)

// request is the JSON contract shared with the Python wrapper. The boolean
// fields mirror the rop3 Rop3() constructor kwargs; the Python side supplies the
// same defaults (rop/frame/avoid_canary on).
type request struct {
	Method       string   `json:"method"` // gadgets | find_op | ropchain | describe
	Binaries     []string `json:"binaries"`
	Base         []string `json:"base"`
	Badchars     []string `json:"badchars"`
	BadcharBytes []string `json:"badchar_bytes"`
	Arch         string   `json:"arch"`
	Raw          bool     `json:"raw"`
	Symbols      bool     `json:"symbols"`
	Depth        int      `json:"depth"`
	Jobs         int      `json:"jobs"`

	Rop          bool `json:"rop"`
	Jop          bool `json:"jop"`
	Retf         bool `json:"retf"`
	RetImm       bool `json:"ret_imm"`
	All          bool `json:"all"`
	Frame        bool `json:"frame"`
	Ropblock     bool `json:"ropblock"`
	RegAliases   bool `json:"reg_aliases"`
	AllowUndet   bool `json:"allow_undeterministic"`
	AllowComplex bool `json:"allow_complex_mem"`
	AllowSeg     bool `json:"allow_segment_override"`
	KeepContra   bool `json:"keep_contradictory"`
	AvoidCanary  bool `json:"avoid_canary"`

	Op         string   `json:"op"`
	Operands   []string `json:"operands"`
	Ropfile    string   `json:"ropfile"`
	Exhaustive bool     `json:"exhaustive"`
}

type response struct {
	OK     bool  `json:"ok"`
	Error  string `json:"error,omitempty"`
	Chains bool   `json:"chains,omitempty"` // find_op: data is a list of chains
	Data   any    `json:"data"`
}

func (r *request) flags() int {
	f := gadfinder.ROP
	if !r.Rop {
		f = 0
	}
	set := func(c bool, flag int) {
		if c {
			f |= flag
		}
	}
	set(r.All, gadfinder.KeepDuplicates)
	set(r.Jop, gadfinder.JOP)
	set(r.Retf, gadfinder.RETF)
	set(r.AllowUndet, gadfinder.AllowUndeterministic)
	set(r.AllowComplex, gadfinder.AllowComplexMem)
	set(r.AvoidCanary, gadfinder.AvoidCanary)
	set(r.RetImm, gadfinder.AllowRetImm)
	set(r.RegAliases, gadfinder.AllowRegAliases)
	set(r.KeepContra, gadfinder.KeepContradictory)
	set(!r.Frame, gadfinder.Unframed)
	set(r.AllowSeg, gadfinder.AllowSegmentOverride)
	set(r.Ropblock, gadfinder.Ropblock)
	return f
}

func (r *request) findOpts() gadfinder.FindOpts {
	return gadfinder.FindOpts{
		Bases: r.Base, Badchars: r.Badchars, BadcharBytes: r.BadcharBytes,
		ArchName: r.Arch, Symbols: r.Symbols, Raw: r.Raw,
	}
}

func (r *request) newFinder() *gadfinder.GadFinder {
	jobs := r.Jobs
	if jobs < 1 {
		jobs = 1
	}
	return gadfinder.New(r.Depth, r.flags(), jobs)
}

func gadgetDicts(gs []*gadget.Gadget) []map[string]any {
	out := make([]map[string]any, len(gs))
	for i, g := range gs {
		out[i] = g.ToDict()
	}
	return out
}

func chainDicts(chains [][]*gadget.Gadget) [][]map[string]any {
	out := make([][]map[string]any, len(chains))
	for i, c := range chains {
		out[i] = gadgetDicts(c)
	}
	return out
}

func handle(r *request) response {
	switch r.Method {
	case "gadgets":
		gf := r.newFinder()
		gs, err := gf.Find(r.Binaries, r.findOpts())
		if err != nil {
			return response{Error: err.Error()}
		}
		return response{OK: true, Data: gadgetDicts(gs)}

	case "find_op":
		gf := r.newFinder()
		gs, err := gf.Find(r.Binaries, r.findOpts())
		if err != nil {
			return response{Error: err.Error()}
		}
		res, ferr := gf.FindOp(gs, r.Op, r.Operands)
		if ferr == nil {
			return response{OK: true, Data: gadgetDicts(res)}
		}
		if errorsIsCompound(ferr) {
			step := gadfinder.ChainStep{Op: r.Op, Operands: r.Operands}
			chains, cerr := ropchain.New(gf).Search(gs, []gadfinder.ChainStep{step}, false, 0, nil)
			if cerr != nil && !isNotFound(cerr) {
				return response{Error: cerr.Error()}
			}
			return response{OK: true, Chains: true, Data: chainDicts(chains)}
		}
		return response{Error: ferr.Error()}

	case "ropchain":
		gf := r.newFinder()
		gs, err := gf.Find(r.Binaries, r.findOpts())
		if err != nil {
			return response{Error: err.Error()}
		}
		rawCtx := &ropchain.RawContext{Binaries: r.Binaries, Opt: r.findOpts()}
		chains, cerr := ropchain.New(gf).SearchFromGadgets(gs, r.Ropfile, 0, rawCtx)
		if cerr != nil {
			if isNotFound(cerr) {
				return response{OK: true, Data: [][]map[string]any{}}
			}
			return response{Error: cerr.Error()}
		}
		return response{OK: true, Data: chainDicts(chains)}

	case "describe":
		var infos []map[string]any
		for i, fn := range r.Binaries {
			base := ""
			if i < len(r.Base) {
				base = r.Base[i]
			} else if len(r.Base) == 1 {
				base = r.Base[0]
			}
			data, err := os.ReadFile(fn)
			if err != nil {
				return response{Error: fmt.Sprintf("%s: %v", fn, err)}
			}
			bin, err := binfmt.Load(data, base, r.Arch, r.Raw)
			if err != nil {
				return response{Error: fmt.Sprintf("%s: %v", fn, err)}
			}
			infos = append(infos, binfmt.Describe(bin, fn, len(data), r.Ropblock, r.Frame))
		}
		return response{OK: true, Data: infos}

	default:
		return response{Error: fmt.Sprintf("unknown method %q", r.Method)}
	}
}

func errorsIsCompound(err error) bool { return err == gadfinder.ErrCompoundUnsupported }

func isNotFound(err error) bool {
	_, ok := err.(*gadfinder.RopChainNotFound)
	return ok
}

//export Rop4Call
func Rop4Call(reqJSON *C.char) *C.char {
	var r request
	resp := response{Data: nil}
	if err := json.Unmarshal([]byte(C.GoString(reqJSON)), &r); err != nil {
		resp.Error = "invalid request json: " + err.Error()
	} else {
		resp = handle(&r)
	}
	blob, err := json.Marshal(resp)
	if err != nil {
		blob = []byte(`{"ok":false,"error":"response marshal failed","data":null}`)
	}
	return C.CString(string(blob))
}

//export Rop4Version
func Rop4Version() *C.char { return C.CString(output.Version) }

//export Rop4Free
func Rop4Free(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
