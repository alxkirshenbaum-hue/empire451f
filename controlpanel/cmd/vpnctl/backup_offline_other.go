//go:build !linux

package main
import ("fmt"; "io")
func offlineVerify(args []string, out, stderr io.Writer) int {
 fmt.Fprintln(stderr,"Offline verification requires an isolated Linux recovery host")
 return 2
}
