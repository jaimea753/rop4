package binfmt

import "fmt"

// newPE loads a PE binary. Implemented in the breadth wave (debug/pe).
func newPE(data []byte, base string) (Binary, error) {
	return nil, fmt.Errorf("PE support not yet implemented")
}
