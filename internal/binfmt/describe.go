package binfmt

// Describe returns human-readable metadata about a loaded binary for verbose
// reporting (rop3 Binary.describe). ropblock/framed mirror the runtime search
// flags so the reported algorithm names the search actually run.
func Describe(bin Binary, filename string, size int, ropblock, framed bool) map[string]any {
	a := bin.Arch()
	var sections []map[string]any
	for _, s := range bin.ExecSections() {
		sections = append(sections, map[string]any{
			"name": s.Name, "vaddr": s.Vaddr, "size": len(s.Opcodes),
		})
	}
	info := map[string]any{
		"filename":  filename,
		"format":    bin.Format(),
		"size":      size,
		"arch":      a.Name(),
		"bits":      a.AddressSize() * 8,
		"alignment": a.Alignment(),
		"algorithm": a.ScanName(ropblock, framed),
		"sections":  sections,
	}
	for k, v := range bin.Info() {
		info[k] = v
	}
	return info
}
