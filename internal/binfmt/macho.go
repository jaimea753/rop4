package binfmt

import "fmt"

// newMachO loads a Mach-O binary. Implemented in the breadth wave (debug/macho).
func newMachO(data []byte, base, archName string) (Binary, error) {
	return nil, fmt.Errorf("Mach-O support not yet implemented")
}
