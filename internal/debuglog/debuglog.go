// Package debuglog is rop4's leveled logger (ported from rop3/debug.py). Unlike
// rop3's debug.error, nothing here calls os.Exit: the library stays embeddable
// and only cmd/rop4 decides to exit. Messages go to stderr.
package debuglog

import (
	"fmt"
	"os"
)

var verbose bool

// SetVerbose enables info-level messages.
func SetVerbose(v bool) { verbose = v }

// IsVerbose reports whether info messages are shown.
func IsVerbose() bool { return verbose }

func emit(level, msg string) {
	fmt.Fprintf(os.Stderr, "rop4: %s: %s\n", level, msg)
}

// Info logs only in verbose mode.
func Info(format string, a ...any) {
	if verbose {
		emit("INFO", fmt.Sprintf(format, a...))
	}
}

// Warning always logs.
func Warning(format string, a ...any) { emit("WARNING", fmt.Sprintf(format, a...)) }

// Errorf logs an error (the caller decides whether to exit).
func Errorf(format string, a ...any) { emit("ERROR", fmt.Sprintf(format, a...)) }
