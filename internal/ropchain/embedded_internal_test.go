package ropchain

import (
	"io/fs"
	"testing"

	"github.com/reverseame/rop4/internal/arch"
)

func TestArchToken(t *testing.T) {
	cases := []struct {
		a    arch.Arch
		want string
	}{
		{arch.NewX64(), "amd64"},
		{arch.NewX86(), "x86"},
		{arch.NewAArch64(), "aarch64"},
		{arch.NewRISCV(false), "riscv"},
		{arch.NewRISCV(true), "riscv"},
	}
	for _, c := range cases {
		if got := archToken(c.a); got != c.want {
			t.Errorf("archToken(%s) = %q, want %q", c.a.Name(), got, c.want)
		}
	}
}

// TestEmbeddedChainsParse ensures every bundled chain is embedded and parses as
// valid ROPLang, so a shipped --ropchain <name> never fails on a parse error.
func TestEmbeddedChainsParse(t *testing.T) {
	entries, err := fs.ReadDir(embeddedChains, "chains")
	if err != nil {
		t.Fatalf("read embedded chains: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no embedded chains found")
	}
	for _, e := range entries {
		name := "chains/" + e.Name()
		data, err := embeddedChains.ReadFile(name)
		if err != nil {
			t.Errorf("%s: read: %v", name, err)
			continue
		}
		steps, err := ParseBytes(data, name)
		if err != nil {
			t.Errorf("%s: parse: %v", name, err)
			continue
		}
		if len(steps) == 0 {
			t.Errorf("%s: parsed to zero steps", name)
		}
	}
}

func TestListEmbeddedChains(t *testing.T) {
	avail := listEmbeddedChains()
	for _, name := range []string{"mprotect", "syscall_exec", "turing"} {
		if _, ok := avail[name]; !ok {
			t.Errorf("expected bundled chain %q to be listed; got %v", name, avail)
		}
	}
	if got := avail["turing"]; len(got) != 1 || got[0] != "amd64" {
		t.Errorf("turing arches = %v, want [amd64]", got)
	}
	for _, name := range []string{"mprotect", "syscall_exec"} {
		if got := avail[name]; len(got) != 4 {
			t.Errorf("%s arches = %v, want 4 (aarch64, amd64, riscv, x86)", name, got)
		}
	}
}
