// Local API for owner sessions and operation metadata.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func download(registry *storage.Registry, domain string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", 405)
			return
		}
		session, err := r.Cookie("session")
		if err != nil {
			http.Error(w, "Unauthorized", 401)
			return
		}
		if r.URL.RawQuery != "client=sfa-1.14.4" {
			http.Error(w, "Unsupported client", 400)
			return
		}
		blob, err := registry.IssueSFA1144(r.Context(), session.Value, r.PathValue("id"), domain)
		if err != nil {
			switch {
			case errors.Is(err, status.ErrSession):
				http.Error(w, "Unauthorized", 401)
			case errors.Is(err, sql.ErrNoRows):
				http.NotFound(w, r)
			default:
				status.Unavailable(w)
			}
			return
		}
		defer clear(blob)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="vpn-`+r.PathValue("id")+`.json"`)
		w.Write(blob)
	}
}

func serve(dbPath, socket, domain, keyPath string, keyVersion int64) error {
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
	mux := http.NewServeMux()
	mux.Handle("/", reader.Handler())
	if domain != "" || keyPath != "" {
		if !storage.ValidEndpoint(domain) || keyPath == "" {
			return errors.New("profile downloads require an endpoint domain and vault key file")
		}
		info, err := os.Lstat(keyPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
			return errors.New("private 32-byte vault key file required")
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		cipher, err := vault.New(key)
		clear(key)
		if err != nil {
			return err
		}
		registry, err := storage.Open(context.Background(), dbPath, cipher, keyVersion)
		if err != nil {
			return err
		}
		defer registry.Close()
		sessions.EnableProfileDownloads()
		mux.HandleFunc("GET /api/v1/users/{id}/profiles/download", download(registry, domain))
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	server := http.Server{Handler: sessions.Handler(mux), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	return server.Serve(listener)
}
func main() {
	db := flag.String("db", "/var/lib/vpn-control/state.db", "Existing panel registry")
	socket := flag.String("socket", "/run/vpn-control/api.sock", "Local Unix socket")
	owner := flag.String("bootstrap-owner", "", "Create first independent panel owner and exit")
	domain := flag.String("profile-domain", "", "VPN endpoint domain for profile downloads")
	key := flag.String("vault-key-file", "", "Private vault key file for profile downloads")
	version := flag.Int64("key-version", 1, "Vault key version")
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
	if err := serve(*db, *socket, *domain, *key, *version); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
