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

func initializeRegistry(args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Run registry init on the Linux entry")
	return 2
}

func cutoverLocal(args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Run migration cutover on the Linux entry")
	return 2
}
