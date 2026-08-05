//go:build linux

package main

import (
	"os"
	"strings"
)

// os.Args is empty inside a c-shared library, so the command line comes from procfs.
func processCommandLine() []string {
	raw, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		return os.Args
	}
	trimmed := strings.TrimRight(string(raw), "\x00")
	if trimmed == "" {
		return os.Args
	}
	return strings.Split(trimmed, "\x00")
}
