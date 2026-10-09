package output_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/disasm"
	"github.com/reverseame/rop4/internal/gadget"
	"github.com/reverseame/rop4/internal/operation"
	"github.com/reverseame/rop4/internal/output"
	"github.com/reverseame/rop4/internal/roplang"
)

func setup(t *testing.T) (arch.Arch, *disasm.Engine, *roplang.Parser) {
	t.Helper()
	a := arch.NewX64()
	eng, err := disasm.Open(a.CSArch(), a.CSMode())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	p, err := roplang.New(a)
	if err != nil {
		t.Fatal(err)
	}
	return a, eng, p
}

func makeGadget(t *testing.T, a arch.Arch, eng *disasm.Engine, code []byte, vaddr uint64) *gadget.Gadget {
	t.Helper()
	decodes, err := eng.Disasm(code, vaddr, 0)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]bool, len(decodes))
	last := len(decodes) - 1
	for i, ins := range decodes {
		frame[i] = i == last || a.RestoresReturnAddress(ins)
	}
	return gadget.New("test", a, vaddr, decodes, code, frame)
}

func matchOne(t *testing.T, a arch.Arch, p *roplang.Parser, op string, operands []any, g *gadget.Gadget) *gadget.Gadget {
	t.Helper()
	defn, err := p.GetOp(op)
	if err != nil {
		t.Fatal(err)
	}
	gs, err := operation.MatchGadgets(a, false, defn, operands, []*gadget.Gadget{g}, true)
	if err != nil || len(gs) == 0 {
		t.Fatalf("match %s: %v (%d)", op, err, len(gs))
	}
	return gs[0]
}

func TestOutputGadgetsJSON(t *testing.T) {
	a, eng, _ := setup(t)
	gs := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000),
		makeGadget(t, a, eng, []byte{0x5b, 0xc3}, 0x1010),
	}
	var buf bytes.Buffer
	if err := output.Gadgets(&buf, gs, "json"); err != nil {
		t.Fatal(err)
	}
	var data []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data) != 2 || data[0]["vaddr"] != "0x1000" || data[1]["vaddr"] != "0x1010" {
		t.Fatalf("json vaddrs = %v", data)
	}
	if data[0]["gadget"] != "pop rax ; ret" {
		t.Fatalf("json gadget = %v", data[0]["gadget"])
	}
}

func TestOutputGadgetsCSV(t *testing.T) {
	a, eng, _ := setup(t)
	gs := []*gadget.Gadget{makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000)}
	var buf bytes.Buffer
	if err := output.Gadgets(&buf, gs, "csv"); err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(buf.String()))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// header + 1 row
	if len(rows) != 2 {
		t.Fatalf("csv rows = %d, want 2", len(rows))
	}
	hdr := rows[0]
	col := func(name string) string {
		for i, h := range hdr {
			if h == name {
				return rows[1][i]
			}
		}
		return ""
	}
	if col("vaddr") != "0x1000" || col("gadget") != "pop rax ; ret" || col("bytes") != "58c3" {
		t.Fatalf("csv row = %v", rows[1])
	}
}

func TestOutputGadgetsText(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	a, eng, _ := setup(t)
	var buf bytes.Buffer
	if err := output.Gadgets(&buf, []*gadget.Gadget{makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000)}, "text"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "pop rax ; ret") {
		t.Errorf("text missing gadget: %q", out)
	}
	if strings.Contains(out, "\033") {
		t.Errorf("text contains ANSI escape: %q", out)
	}
}

func TestOutputRopchainsJSON(t *testing.T) {
	a, eng, _ := setup(t)
	chain := []*gadget.Gadget{
		makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000),
		makeGadget(t, a, eng, []byte{0x5b, 0xc3}, 0x1010),
	}
	var buf bytes.Buffer
	if err := output.Ropchains(&buf, [][]*gadget.Gadget{chain}, "json", true); err != nil {
		t.Fatal(err)
	}
	var data [][]map[string]any
	if err := json.Unmarshal(buf.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 || len(data[0]) != 2 {
		t.Fatalf("ropchain json shape = %v", data)
	}
}

func TestOutputRopchainsCSVHasChainIndex(t *testing.T) {
	a, eng, _ := setup(t)
	chain := []*gadget.Gadget{makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000)}
	var buf bytes.Buffer
	if err := output.Ropchains(&buf, [][]*gadget.Gadget{chain}, "csv", true); err != nil {
		t.Fatal(err)
	}
	r := csv.NewReader(strings.NewReader(buf.String()))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0][0] != "chain" || rows[1][0] != "1" {
		t.Fatalf("csv chain index = %v", rows)
	}
}

func TestOutputRopchainsTextNonExhaustiveTakesFirst(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	a, eng, _ := setup(t)
	first := []*gadget.Gadget{makeGadget(t, a, eng, []byte{0x58, 0xc3}, 0x1000)}
	second := []*gadget.Gadget{makeGadget(t, a, eng, []byte{0x5b, 0xc3}, 0x1010)}
	var buf bytes.Buffer
	if err := output.Ropchains(&buf, [][]*gadget.Gadget{first, second}, "text", false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "pop rax ; ret") {
		t.Errorf("first chain missing: %q", out)
	}
	if strings.Contains(out, "pop rbx ; ret") {
		t.Errorf("non-exhaustive text should print only the first chain: %q", out)
	}
}

func TestOutputGadgetsTuple(t *testing.T) {
	a, eng, p := setup(t)
	g := makeGadget(t, a, eng, []byte{0x48, 0x89, 0xc7, 0xc3}, 0x1000) // mov rdi, rax ; ret
	matched := matchOne(t, a, p, "mov", []any{"rdi", "rax"}, g)
	var buf bytes.Buffer
	if err := output.Gadgets(&buf, []*gadget.Gadget{matched}, "tuple"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "@ 0x1000]: ⟨mov, rdi, rax, {rdi}, {rax}⟩") {
		t.Fatalf("tuple output = %q", buf.String())
	}
}
