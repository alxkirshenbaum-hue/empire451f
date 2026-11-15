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
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

func execute(args []string, out, stderr io.Writer) int {
	if len(args) >= 2 && args[0] == "backup" && args[1] == "offline-verify" {
		return offlineVerify(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "backup" && args[1] == "configure" {
		return configureBackup(args[2:], out, stderr)
	}
	if ownerCLIMode(args) {
		return ownerCLI(args, out, stderr)
	}
	if len(args) >= 2 && args[0] == "worker" && args[1] == "reconcile" {
		return workerReconcile(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "user" && (args[1] == "disable" || args[1] == "enable" || args[1] == "delete") {
		return mutateLocalUser(args[1], args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "cred" && (args[1] == "rotate" || args[1] == "revoke") {
		return mutateLocalUser(args[1], args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "registry" && args[1] == "init" {
		return initializeRegistry(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "migration" && args[1] == "cutover" {
		return cutoverLocal(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "worker" && args[1] == "once" {
		return workerOnce(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "user" && args[1] == "create" {
		return createLocalUser(args[2:], out, stderr)
	}
	if len(args) >= 2 && args[0] == "migration" && (args[1] == "execute" || args[1] == "reverse-export") {
		return executeMigration(args[1], args[2:], out, stderr)
	}
	if len(args) >= 1 && args[0] == "auth" {
		if len(args) == 2 && args[1] == "whoami" {
			return authWhoami(out, stderr)
		}
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
	cookie, err := ownerCookie()
	if err != nil {
		fmt.Fprintln(stderr, "Private owner session unavailable")
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
