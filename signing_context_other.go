//go:build !linux && !darwin && !windows

package main

import "os"

func processCommandLine() []string {
	return os.Args
}
