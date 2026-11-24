package caddy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var ErrRuntime = errors.New("private Caddy admin operation failed")

type UnixRuntime struct {
	client          *http.Client
	validateCommand []string
}

// NewUnixRuntime never opens TCP, uses environment proxies or follows redirects.
// Command is trusted deployment policy (namespace + unprivileged identity),
// never request input. It must accept JSON configuration on standard input.
func NewUnixRuntime(socket string, validateCommand []string) (*UnixRuntime, error) {
	if !filepath.IsAbs(socket) || len(validateCommand) == 0 {
		return nil, ErrInput
	}
	check := func() error {
		dir, err := os.Lstat(filepath.Dir(socket))
		if err != nil || !dir.IsDir() || dir.Mode().Perm()&0007 != 0 {
			return ErrRuntime
		}
		info, err := os.Lstat(socket)
		if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
			return ErrRuntime
		}
		return nil
	}
	if err := check(); err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := check(); err != nil {
			return nil, err
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	return &UnixRuntime{client: &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRuntime }}, validateCommand: append([]string(nil), validateCommand...)}, nil
}

func (r *UnixRuntime) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrRuntime
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, ErrRuntime
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrRuntime
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		clear(data)
		return nil, ErrRuntime
	}
	return data, nil
}

func (r *UnixRuntime) Read(ctx context.Context) ([]byte, error) {
	return r.request(ctx, "GET", "/config/", nil)
}
func (r *UnixRuntime) Load(ctx context.Context, config []byte) error {
	data, err := r.request(ctx, "POST", "/load", config)
	clear(data)
	return err
}
func (r *UnixRuntime) Validate(ctx context.Context, config []byte) error {
	cmd := exec.CommandContext(ctx, r.validateCommand[0], r.validateCommand[1:]...)
	cmd.Stdin = bytes.NewReader(config)
	// Discard stdout/stderr: Caddy diagnostics can contain configuration secrets.
	if cmd.Run() != nil {
		return ErrRuntime
	}
	return nil
}
