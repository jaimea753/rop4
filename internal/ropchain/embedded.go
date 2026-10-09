package ropchain

import "embed"

// embeddedChains holds the ROPLang example chains shipped inside the rop4 binary.
// A bare --ropchain name (one that is not an existing file) resolves to
// chains/<name>_<arch>.txt here, selecting the variant for the target binary's
// detected architecture. Mirrors the //go:embed catalog pattern in
// internal/roplang/yaml.go.
//
//go:embed chains/*.txt
var embeddedChains embed.FS
