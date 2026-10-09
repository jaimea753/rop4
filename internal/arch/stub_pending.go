package arch

// Pending architectures. These constructors exist so the binary loaders can
// reference them while the full AArch64 / RISC-V ports are being written in the
// breadth wave. They MUST be replaced with real implementations; until then a
// loader that reaches them should treat the result as unsupported.
//
// They return a minimal placeholder that only reports identity; using one for
// an actual scan is a bug the breadth wave removes.

// NewAArch64 is a placeholder (replaced in aarch64.go).
func NewAArch64() Arch { panic("arch: AArch64 not yet implemented (breadth wave)") }

// NewRISCV is a placeholder (replaced in riscv.go).
func NewRISCV(compressed bool) Arch { panic("arch: RISC-V not yet implemented (breadth wave)") }
