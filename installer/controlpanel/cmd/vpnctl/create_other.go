//go:build !linux

package main

import (
	"fmt"
	"io"
)

func configureBackup(args []string,out,stderr io.Writer) int {fmt.Fprintln(stderr,"Configure the public backup recipient on the Linux entry");return 2}

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

func mutateLocalUser(action string, args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Run user changes on the Linux entry")
	return 2
}

func workerReconcile(args []string, out, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Run worker reconciliation on the Linux entry")
	return 2
}
