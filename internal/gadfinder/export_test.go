package gadfinder

import (
	"github.com/reverseame/rop4/internal/arch"
	"github.com/reverseame/rop4/internal/binfmt"
	"github.com/reverseame/rop4/internal/gadget"
)

// CanaryBytesForTest exposes the default canary byte set.
var CanaryBytesForTest = canaryBytes

// AvoidBytesForTest exposes avoidBytes.
func (gf *GadFinder) AvoidBytesForTest(bc []string) map[byte]bool { return gf.avoidBytes(bc) }

// AddrCanaryScoreForTest exposes addrCanaryScore.
func (gf *GadFinder) AddrCanaryScoreForTest(g *gadget.Gadget, avoid map[byte]bool) int {
	return gf.addrCanaryScore(g, avoid)
}

// SetArchForTest sets the detected architecture (normally set by scanning a
// binary) so matcher/chain paths can run against synthetic gadgets.
func (gf *GadFinder) SetArchForTest(a arch.Arch) { gf.arch = a }

// NearestSymbolForTest exercises the nearest-symbol annotation (symbolTable).
func NearestSymbolForTest(syms []binfmt.Symbol, vaddr uint64) string {
	return newSymbolTable(syms).nearest(vaddr)
}
