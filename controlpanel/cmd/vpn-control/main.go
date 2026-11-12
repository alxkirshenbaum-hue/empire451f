// Read-only local API for an existing panel registry and existing admin sessions.
package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func serve(dbPath, socket string) error {
	info, err := os.Lstat(filepath.Dir(socket))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("socket directory must be private (0700)")
	}
	reader, err := status.Open(dbPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	server := http.Server{Handler: reader.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	return server.Serve(listener)
}
func main() {
	db := flag.String("db", "/var/lib/vpn-control/state.db", "Existing panel registry")
	socket := flag.String("socket", "/run/vpn-control/api.sock", "Local Unix socket")
	flag.Parse()
	if err := serve(*db, *socket); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
