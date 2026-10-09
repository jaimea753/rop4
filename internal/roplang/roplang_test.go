package roplang_test

import (
	"testing"

	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/roplang"
)

func TestCatalogLoadsX64(t *testing.T) {
	p, err := roplang.New(arch.NewX64())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mov, err := p.GetOp("mov")
	if err != nil {
		t.Fatalf("GetOp(mov): %v", err)
	}
	if mov.Operands != 2 {
		t.Fatalf("mov operands = %d, want 2", mov.Operands)
	}
	if len(mov.DstRoles) != 1 || mov.DstRoles[0] != "op1" {
		t.Fatalf("mov dst = %v", mov.DstRoles)
	}
	if len(mov.SrcRoles) != 1 || mov.SrcRoles[0] != "op2" {
		t.Fatalf("mov src = %v", mov.SrcRoles)
	}
	if len(mov.Realizations) == 0 {
		t.Fatalf("mov has no realizations")
	}
	for i, r := range mov.Realizations {
		if !r.IsSingleGadget() {
			t.Fatalf("mov realization %d is not single-gadget (x86 mov is a primitive)", i)
		}
	}

	// spa reuses add via an operation reference -> compound (not single gadget).
	spa, err := p.GetOp("spa")
	if err != nil {
		t.Fatalf("GetOp(spa): %v", err)
	}
	compound := false
	for _, r := range spa.Realizations {
		if !r.IsSingleGadget() {
			compound = true
		}
	}
	if !compound {
		t.Fatalf("spa should be compound (operation ref)")
	}

	// eqc writes REG_FLAGS, resolved to the concrete x86-64 flags register.
	eqc, err := p.GetOp("eqc")
	if err != nil {
		t.Fatalf("GetOp(eqc): %v", err)
	}
	if len(eqc.DstRoles) != 1 || eqc.DstRoles[0] != "rflags" {
		t.Fatalf("eqc dst roles = %v, want [rflags]", eqc.DstRoles)
	}

	if _, err := p.GetOp("nope"); err == nil {
		t.Fatalf("expected error for unknown operation")
	}
}
