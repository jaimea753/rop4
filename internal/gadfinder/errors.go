package gadfinder

// RopChainNotFound is the assembler's error type (rop3 ropchain.RopChainNotFound).
// It lives in gadfinder because ClassifyRopchain raises it and the ropchain
// package imports gadfinder (not the reverse).
type RopChainNotFound struct{ Msg string }

func (e *RopChainNotFound) Error() string {
	if e.Msg == "" {
		return "no suitable ropchain combination found"
	}
	return e.Msg
}
