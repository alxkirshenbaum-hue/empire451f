// Local API for owner sessions and operation metadata.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	sessions, err := auth.Open(dbPath)
	if err != nil {
		return err
	}
	defer sessions.Close()
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	server := http.Server{Handler: sessions.Handler(reader.Handler()), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	return server.Serve(listener)
}
func main() {
	db := flag.String("db", "/var/lib/vpn-control/state.db", "Existing panel registry")
	socket := flag.String("socket", "/run/vpn-control/api.sock", "Local Unix socket")
	owner := flag.String("bootstrap-owner", "", "Create first independent panel owner and exit")
	flag.Parse()
	if *owner != "" {
		sessions, err := auth.Open(*db)
		if err == nil {
			defer sessions.Close()
			var password []byte
			password, err = exec.Command("systemd-ask-password", "New panel owner password:").Output()
			if err == nil {
				err = sessions.Bootstrap(context.Background(), *owner, strings.TrimSuffix(string(password), "\n"))
				clear(password)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := serve(*db, *socket); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
