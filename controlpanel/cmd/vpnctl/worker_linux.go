//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

type workerPolicy struct {
	Installation string   `json:"installation"`
	OwnerRun     string   `json:"owner_run"`
	Socket       string   `json:"socket"`
	Helper       string   `json:"helper"`
	Validate     []string `json:"validate_command"`
	Probe        []string `json:"probe_command"`
}

func rootFile(path string, private bool) error {
	if !filepath.IsAbs(path) {
		return caddy.ErrInput
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return caddy.ErrInput
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return caddy.ErrInput
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm()&0077 != 0 {
		return caddy.ErrInput
	}
	return nil
}

func readWorkerPolicy(path, installation, run string) (workerPolicy, error) {
	var p workerPolicy
	if err := rootFile(path, true); err != nil {
		return p, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	defer clear(data)
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || p.Installation != installation || p.OwnerRun != run || !filepath.IsAbs(p.Socket) || len(p.Validate) == 0 || len(p.Probe) == 0 {
		return p, caddy.ErrInput
	}
	var tail any
	if !errors.Is(d.Decode(&tail), io.EOF) {
		return p, caddy.ErrInput
	}
	for _, file := range []string{p.Helper, p.Validate[0], p.Probe[0]} {
		if err = rootFile(file, false); err != nil {
			return p, err
		}
	}
	for _, command := range [][]string{p.Validate, p.Probe} {
		for _, argument := range command[1:] {
			if filepath.IsAbs(argument) {
				if err = rootFile(argument, false); err != nil {
					return p, err
				}
			}
		}
	}
	return p, nil
}

func commandProbe(command []string) func(context.Context, string, vault.PlainSecret) error {
	return func(ctx context.Context, login string, secret vault.PlainSecret) error {
		data, err := json.Marshal([]string{login, string(secret)})
		if err != nil {
			return caddy.ErrInput
		}
		defer clear(data)
		ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		cmd.Stdin = bytes.NewReader(data)
		if cmd.Run() != nil {
			return errors.New("fresh Naive and site verification failed")
		}
		return nil
	}
}

// Adapt the actual file with the same namespace/identity prefix as validation.
// This detects live unmanaged drift before preparing any auth mutation.
func caddyBaseline(ctx context.Context, policy workerPolicy, runtime caddy.Runtime, caddyfile string) error {
	command := policy.Validate
	n := len(command)
	if n < 4 || command[n-3] != "validate" || command[n-2] != "--config" || command[n-1] != "-" {
		return caddy.ErrInput
	}
	args := append(append([]string(nil), command[1:n-3]...), "adapt", "--config", caddyfile, "--adapter", "caddyfile")
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], args...)
	expected, err := cmd.Output()
	if err != nil {
		return caddy.ErrRuntime
	}
	defer clear(expected)
	actual, err := runtime.Read(ctx)
	if err != nil {
		return err
	}
	defer clear(actual)
	if !caddy.ConfigEqual(actual, expected) {
		return caddy.ErrDrift
	}
	return nil
}

func workerOnce(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("worker once", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	installation := flags.String("installation", "", "Installation ID")
	run := flags.String("owner-run", "", "Approved writer run")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !installationID.MatchString(*installation) || !status.ValidID(*run) {
		fmt.Fprintln(stderr, "Invalid installation or owner run")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run as root on the entry")
		return 3
	}
	policy, err := readWorkerPolicy(filepath.Join("/etc/vpn-control", "worker-"+*installation+".json"), *installation, *run)
	if err != nil {
		fmt.Fprintln(stderr, "Private approved worker policy unavailable")
		return 4
	}
	runtime, err := caddy.NewUnixRuntime(policy.Socket, policy.Validate)
	if err != nil {
		fmt.Fprintln(stderr, "Private Caddy runtime unavailable")
		return 5
	}
	w := createCaddyWorker{state: filepath.Join("/var/lib/empire-vpn", *installation), config: "/etc/empire-vpn", lock: "/run/lock/empire-vpn.lock", panel: "/var/lib/vpn-control", run: *run, helper: policy.Helper, runtime: runtime, probe: commandProbe(policy.Probe)}
	w.baseline = func(ctx context.Context) error {
		return caddyBaseline(ctx, policy, runtime, filepath.Join(w.config, *installation, "Caddyfile"))
	}
	receipt, err := w.once()
	if err != nil {
		fmt.Fprintln(stderr, "Worker stopped; inspect protected operation state before retrying")
		return 5
	}
	state := "idle"
	if receipt.OperationID != "" {
		state = "completed"
	}
	if json.NewEncoder(out).Encode(struct {
		State     string `json:"state"`
		Operation string `json:"operation_id,omitempty"`
	}{state, receipt.OperationID}) != nil {
		return 9
	}
	return 0
}
