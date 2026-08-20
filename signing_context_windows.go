//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func processCommandLine() []string {
	raw := windows.GetCommandLine()
	if raw == nil {
		return os.Args
	}

	args, err := windows.DecomposeCommandLine(windows.UTF16PtrToString(raw))
	if err != nil || len(args) == 0 {
		return os.Args
	}
	return args
}
