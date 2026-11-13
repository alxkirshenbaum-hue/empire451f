//go:build !linux

package main

import (
	"fmt"
	"io"
)

func createLocalUser(args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Run vpnctl user create on the Linux entry")
	return 2
}

func workerOnce(args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Run vpnctl worker once on the Linux entry")
	return 2
}
