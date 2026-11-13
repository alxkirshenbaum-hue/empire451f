package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

func execute(args []string, out, stderr io.Writer) int {
	if len(args) >= 2 && args[0] == "user" && args[1] == "create" {
		return createLocalUser(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "migration" && (args[1] == "execute" || args[1] == "reverse-export") {
		return executeMigration(args[1], args[2:], out, stderr)
	}
	if len(args) >= 1 && args[0] == "auth" {
		return authCommand(args[1:], stderr)
	}
	if len(args) < 3 || args[0] != "operation" || args[1] != "show" || !status.ValidID(args[2]) {
		fmt.Fprintln(stderr, "Usage: vpnctl operation show ID [--json | --quiet]")
		return 2
	}
	mode := ""
	if len(args) > 3 {
		if len(args) != 4 || (args[3] != "--json" && args[3] != "--quiet") {
			fmt.Fprintln(stderr, "Invalid output option")
			return 2
		}
		mode = args[3]
	}
	socket := os.Getenv("VPNCTL_SOCKET")
	if socket == "" {
		socket = "/run/vpn-control/api.sock"
	}
	sessionFile := os.Getenv("VPNCTL_SESSION_FILE")
	if sessionFile == "" {
		fmt.Fprintln(stderr, "Set VPNCTL_SESSION_FILE to a private session file")
		return 3
	}
	f, err := os.Open(sessionFile)
	if err != nil {
		fmt.Fprintln(stderr, "Cannot read session file")
		return 3
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		fmt.Fprintln(stderr, "Session file must be private")
		return 3
	}
	b, err := io.ReadAll(io.LimitReader(f, 515))
	token := strings.TrimSpace(string(b))
	if err != nil || len(b) > 514 || token == "" || len(token) > 512 {
		fmt.Fprintln(stderr, "Invalid session file")
		return 3
	}
	cookie := http.Cookie{Name: "session", Value: token}
	if err := cookie.Valid(); err != nil {
		fmt.Fprintln(stderr, "Invalid session token")
		return 3
	}
	client := localClient(socket)
	defer client.CloseIdleConnections()
	req, err := http.NewRequest("GET", "http://localhost/api/v1/operations/"+args[2], nil)
	if err != nil {
		return 9
	}
	req.AddCookie(&cookie)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(stderr, "Local status API unavailable")
		return 5
	}
	defer resp.Body.Close()
	var result status.Response
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		fmt.Fprintln(stderr, "Invalid API response")
		return 9
	}
	if mode == "--json" {
		if err = json.NewEncoder(out).Encode(result); err != nil {
			return 9
		}
	}
	if resp.StatusCode != 200 || result.Data == nil {
		if mode != "--json" && result.Error != nil {
			fmt.Fprintln(stderr, result.Error.Code)
		}
		switch resp.StatusCode {
		case 401, 403:
			return 3
		case 400, 404:
			return 2
		case 503:
			return 5
		default:
			return 9
		}
	}
	if mode == "" {
		fmt.Fprintf(out, "%s %s %s\n", result.Data.ID, result.Data.Kind, result.Data.Status)
		for _, step := range result.Data.Steps {
			fmt.Fprintf(out, "  %d %s %s\n", step.Number, step.Name, step.State)
		}
	}
	return 0
}
func main() { os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr)) }

func localClient(socket string) *http.Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}
