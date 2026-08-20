//go:build darwin

package main

import (
	"bytes"
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

func processCommandLine() []string {
	raw, err := unix.SysctlRaw("kern.procargs2", os.Getpid())
	if err != nil || len(raw) < 4 {
		return os.Args
	}

	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	if argc <= 0 {
		return os.Args
	}

	rest := raw[4:]
	// Skip the executable path and the NUL padding that follows it.
	execEnd := bytes.IndexByte(rest, 0)
	if execEnd < 0 {
		return os.Args
	}
	rest = rest[execEnd:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}

	args := make([]string, 0, argc)
	for i := 0; i < argc && len(rest) > 0; i++ {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			args = append(args, string(rest))
			break
		}
		args = append(args, string(rest[:end]))
		rest = rest[end+1:]
	}

	if len(args) == 0 {
		return os.Args
	}
	return args
}
