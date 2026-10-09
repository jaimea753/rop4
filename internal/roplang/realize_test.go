package roplang_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/operation"
	"github.com/reverseame/rop4/internal/roplang"
)

// chainKey renders a realization chain as its ordered step-data joined by " | ".
func chainKey(chain []operation.Step) string {
	parts := make([]string, len(chain))
	for i, s := range chain {
		parts[i] = s.Data
	}
	return strings.Join(parts, " | ")
}

// realizeSet returns the set of realization chains for op under binding.
func realizeSet(t *testing.T, p *roplang.Parser, op string, binding map[string]any) (map[string]bool, bool) {
	t.Helper()
	defn, err := p.GetOp(op)
	if err != nil {
		t.Fatalf("GetOp(%s): %v", op, err)
	}
	chains, err := operation.Realize(defn, binding, p.Resolve())
	if err != nil {
		t.Fatalf("Realize(%s): %v", op, err)
	}
	set := map[string]bool{}
	for _, c := range chains {
		set[chainKey(c)] = true
	}
	return set, defn.Available
}

func keyify(chains [][]string) map[string]bool {
	set := map[string]bool{}
	for _, c := range chains {
		set[strings.Join(c, " | ")] = true
	}
	return set
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCompoundRealizationsX64 pins the complete set of primitive-step chains
// every compound (compose:) operation expands to on x86-64 (rop3
// test_ropchain._COMPOUND_ARCHES). A roplang/*.yaml change surfaces here.
func TestCompoundRealizationsX64(t *testing.T) {
	p, err := roplang.New(arch.NewX64())
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"op1": "rax", "op2": "rbx", "op3": "rcx"}

	expected := map[string][][]string{
		"eqc":   {{"sub(rax, rbx)", "neg(rax)"}},
		"ltc":   {{"sub(rax, rbx)"}},
		"lsd":   {{"lc(TMP_REG)", "neg(rax)", "and(rax, TMP_REG)"}},
		"gsp":   {{"mov(rax, rsp)"}},
		"spa":   {{"add(rsp, rax)"}},
		"sps":   {{"sub(rsp, rax)"}},
		"pivot": {{"lc(rbp)", "leave()"}},
		"gcf-eqc": {
			{"lc(TMP_REG)", "sub(rbx, rcx)", "neg(rbx)", "adc(rax, TMP_REG)"},
			{"lc(TMP_REG)", "sub(rbx, rcx)", "neg(rbx)", "sbb(rax, TMP_REG)", "neg(rax)"},
			{"lc(rax)", "sub(rbx, rcx)", "neg(rbx)", "rcl(rax)"},
		},
		"gcf-ltc": {
			{"lc(TMP_REG)", "sub(rbx, rcx)", "adc(rax, TMP_REG)"},
			{"lc(TMP_REG)", "sub(rbx, rcx)", "sbb(rax, TMP_REG)", "neg(rax)"},
			{"lc(rax)", "sub(rbx, rcx)", "rcl(rax)"},
		},
		"jmp": {
			{"mov(rbp, rax)", "leave()"},
			{"add(rsp, rax)"},
		},
	}

	for op, want := range expected {
		got, available := realizeSet(t, p, op, binding)
		wantSet := keyify(want)
		if !available {
			t.Errorf("%s: expected available on x86-64", op)
		}
		if len(got) != len(wantSet) || !equalSets(got, wantSet) {
			t.Errorf("%s realizations:\n got  %v\n want %v", op, sortedKeys(got), sortedKeys(wantSet))
		}
	}
}

func equalSets(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// TestCarryOpsUnavailableOnRISCV asserts the carry/condition operations are
// marked unavailable on RISC-V (no flags register), i.e. realize yields nothing.
func TestCarryOpsUnavailableOnRISCV(t *testing.T) {
	p, err := roplang.New(arch.NewRISCV(false))
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"op1": "a0", "op2": "a1", "op3": "a2"}
	for _, op := range []string{"eqc", "ltc", "gcf-eqc", "gcf-ltc"} {
		got, available := realizeSet(t, p, op, binding)
		if available {
			t.Errorf("%s should be unavailable on RISC-V", op)
		}
		if len(got) != 0 {
			t.Errorf("%s should produce no realization on RISC-V, got %v", op, sortedKeys(got))
		}
	}
}
