package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
)

func authCommand(args []string, stderr io.Writer) int {
	login := len(args) == 2 && args[0] == "login"
	if !login && !(len(args) == 1 && args[0] == "logout") {
		fmt.Fprintln(stderr, "Usage: vpnctl auth login USERNAME | vpnctl auth logout")
		return 2
	}
	path := os.Getenv("VPNCTL_SESSION_FILE")
	dir, err := os.Lstat(filepath.Dir(path))
	if path == "" || err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		fmt.Fprintln(stderr, "Set VPNCTL_SESSION_FILE inside a private directory")
		return 3
	}
	socket := os.Getenv("VPNCTL_SOCKET")
	if socket == "" {
		socket = "/run/vpn-control/api.sock"
	}
	client := localClient(socket)
	defer client.CloseIdleConnections()
	var body bytes.Buffer
	var token string
	if login {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintln(stderr, "Cannot create session file; log out of an existing session first")
			return 3
		}
		defer f.Close()
		saved := false
		defer func() {
			if !saved {
				os.Remove(path)
			}
		}()
		pw, err := exec.Command("systemd-ask-password", "Panel owner password:").Output()
		if err != nil {
			return 3
		}
		json.NewEncoder(&body).Encode(map[string]string{"username": args[1], "password": strings.TrimSuffix(string(pw), "\n")})
		clear(pw)
		resp, err := postAuth(client, "login", &body, "")
		if err != nil {
			fmt.Fprintln(stderr, "Local API unavailable")
			return 5
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			fmt.Fprintln(stderr, resp.Status)
			return 3
		}
		for _, c := range resp.Cookies() {
			if c.Name == "session" {
				token = c.Value
			}
		}
		if token == "" {
			return 9
		}
		if _, err = f.WriteString(token + "\n"); err != nil {
			return 9
		}
		if err = f.Close(); err != nil {
			return 9
		}
		saved = true
		return 0
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 514 {
		return 3
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 3
	}
	token = strings.TrimSpace(string(b))
	resp, err := postAuth(client, "logout", &body, token)
	if err != nil {
		fmt.Fprintln(stderr, "Local API unavailable")
		return 5
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 && resp.StatusCode != 401 {
		fmt.Fprintln(stderr, resp.Status)
		return 3
	}
	if err = os.Remove(path); err != nil {
		return 9
	}
	return 0
}
func postAuth(client *http.Client, action string, body io.Reader, token string) (*http.Response, error) {
	req, err := http.NewRequest("POST", "http://localhost/api/v1/auth/"+action, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", auth.Origin)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: token})
		req.Header.Set("X-CSRF-Token", auth.CSRF(token))
	}
	return client.Do(req)
}
