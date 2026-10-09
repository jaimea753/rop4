package disasm

import "testing"

// pop rdi ; ret  ==  5f c3
func TestX86DecodeAndRegs(t *testing.T) {
	e, err := Open(ArchX86, Mode64)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	insns, err := e.Disasm([]byte{0x5f, 0xc3}, 0x1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(insns) != 2 {
		t.Fatalf("want 2 insns, got %d", len(insns))
	}
	if insns[0].Mnemonic != "pop" || insns[0].OpStr != "rdi" {
		t.Errorf("insn0 = %q %q, want pop rdi", insns[0].Mnemonic, insns[0].OpStr)
	}
	if insns[1].Mnemonic != "ret" {
		t.Errorf("insn1 = %q, want ret", insns[1].Mnemonic)
	}
	// pop rdi: one register operand named rdi.
	if len(insns[0].Operands) != 1 || insns[0].Operands[0].Type != OpReg {
		t.Fatalf("pop operands = %+v", insns[0].Operands)
	}
	if n := e.RegName(insns[0].Operands[0].Reg); n != "rdi" {
		t.Errorf("reg name = %q, want rdi", n)
	}
	// regs_access must work on x86: pop writes rdi (and rsp).
	if !insns[0].RegsOK {
		t.Fatal("expected RegsOK for x86 pop")
	}
	wrote := map[string]bool{}
	for _, r := range insns[0].RegsWritten {
		wrote[e.RegName(r)] = true
	}
	if !wrote["rdi"] {
		t.Errorf("pop rdi written-regs = %v, want rdi present", wrote)
	}
}

// mov rax, [rdi+0x10]  ==  48 8b 47 10  : exercises the mem operand fields.
func TestX86MemOperand(t *testing.T) {
	e, _ := Open(ArchX86, Mode64)
	defer e.Close()
	insns, _ := e.Disasm([]byte{0x48, 0x8b, 0x47, 0x10}, 0, 0)
	if len(insns) != 1 {
		t.Fatalf("want 1 insn, got %d", len(insns))
	}
	var mem *Operand
	for i := range insns[0].Operands {
		if insns[0].Operands[i].Type == OpMem {
			mem = &insns[0].Operands[i]
		}
	}
	if mem == nil {
		t.Fatalf("no mem operand in %q %q", insns[0].Mnemonic, insns[0].OpStr)
	}
	if e.RegName(mem.Mem.Base) != "rdi" || mem.Mem.Disp != 0x10 {
		t.Errorf("mem base=%q disp=%#x, want rdi 0x10", e.RegName(mem.Mem.Base), mem.Mem.Disp)
	}
}

// RISC-V: ret == c.jr ra (compressed, 82 80) and plain ret (jalr x0,0(ra) = 67 80 00 00).
func TestRISCVDecode(t *testing.T) {
	e, err := Open(ArchRISCV, ModeRV64|ModeRVC)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	insns, err := e.Disasm([]byte{0x82, 0x80}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(insns) != 1 {
		t.Fatalf("want 1 insn, got %d (compressed decode failed?)", len(insns))
	}
	t.Logf("riscv decoded: %q %q regsOK=%v", insns[0].Mnemonic, insns[0].OpStr, insns[0].RegsOK)
	if insns[0].Mnemonic == "" {
		t.Error("empty mnemonic for c.jr ra")
	}
}

func TestVersion(t *testing.T) {
	maj, min := Version()
	t.Logf("libcapstone %d.%d", maj, min)
	if maj < 5 {
		t.Fatalf("need capstone >= 5, got %d.%d", maj, min)
	}
}
