//go:build !linux

package main

import (
	"fmt"
	"io"
)

func portableCommand(action string, args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Portable import requires a protected Linux first-start staging host")
	return 2
}
