//go:build linux

package caddy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestInstalledCaddyUnixAdapter(t *testing.T) {
	if os.Getenv("VPN_TEST_CADDY_ADAPTER") != "1" {
		t.Skip("isolated installed-Caddy test")
	}
	interfaces, err := os.ReadDir("/sys/class/net")
	if err != nil || len(interfaces) != 1 || interfaces[0].Name() != "lo" {
		t.Fatal("requires isolated loopback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	port, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := port.Addr().String()
	port.Close()
	socket := filepath.Join(dir, "admin.sock")
	config := map[string]any{"admin": map[string]any{"listen": "unix/" + socket}, "apps": map[string]any{"http": map[string]any{"servers": map[string]any{"lab": map[string]any{"listen": []string{addr}, "routes": []any{map[string]any{"handle": []any{
		map[string]any{"handler": "forward_proxy", "hosts": []string{"lab.example"}, "auth_credentials": []string{credential("canary", "old")}, "acl": []any{map[string]any{"subjects": []string{"127.0.0.0/8"}, "allow": true}}},
		map[string]any{"handler": "static_response", "body": "site-baseline"},
	}}}}}}}}
	raw, _ := json.Marshal(config)
	file := filepath.Join(dir, "config.json")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	binary := "/opt/empire-vpn/bin/caddy"
	cmd := exec.CommandContext(ctx, binary, "run", "--config", file)
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for i := 0; i < 100; i++ {
		if _, err = os.Stat(socket); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal("private admin socket unavailable")
	}
	rt, err := NewUnixRuntime(socket, []string{binary, "validate", "--config", "-"})
	if err != nil {
		t.Fatal(err)
	}
	probe := func(login, password string, want bool) error {
		c, e := net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			return ErrRuntime
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		auth := base64.StdEncoding.EncodeToString([]byte(login + ":" + password))
		_, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", echo.Addr(), echo.Addr(), auth)
		if e != nil {
			return ErrRuntime
		}
		reader := bufio.NewReader(c)
		resp, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if e != nil {
			return ErrRuntime
		}
		if !want {
			if resp.StatusCode == 407 {
				return nil
			}
			return ErrRuntime
		}
		if resp.StatusCode != 200 {
			return ErrRuntime
		}
		if _, e = c.Write([]byte("probe")); e != nil {
			return ErrRuntime
		}
		data := make([]byte, 5)
		if _, e = io.ReadFull(reader, data); e != nil || string(data) != "probe" {
			return ErrRuntime
		}
		return nil
	}
	verify := func(context.Context) error {
		if e := probe("new", "secret", true); e != nil {
			return e
		}
		if e := probe("new", "wrong", false); e != nil {
			return e
		}
		if e := probe("canary", "old", true); e != nil {
			return e
		}
		client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
		req, e := http.NewRequest("GET", "http://"+addr, nil)
		if e != nil {
			return ErrRuntime
		}
		req.Host = "lab.example"
		resp, e := client.Do(req)
		if e != nil {
			return ErrRuntime
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(body) != "site-baseline" {
			return ErrRuntime
		}
		return nil
	}
	if err = probe("canary", "old", true); err != nil {
		t.Fatal("baseline CONNECT failed")
	}
	p, err := Prepare(ctx, rt, dir, "live-op", 1, "new", "secret")
	if err != nil {
		t.Fatal("prepare failed", err)
	}
	defer p.Clear()
	if err = p.Apply(ctx, rt, verify); err != nil {
		t.Fatal("apply/verify failed", err)
	}
	if err = p.Verify(ctx, rt, verify); err != nil {
		t.Fatal("recovery verify failed", err)
	}
	if err = p.Rollback(ctx, rt, func(context.Context) error { return probe("canary", "old", true) }); err != nil {
		t.Fatal("rollback failed", err)
	}
	if err = probe("new", "secret", false); err != nil {
		t.Fatal("new credential survived rollback")
	}
	if err = os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = NewUnixRuntime(socket, []string{binary}); err == nil {
		t.Fatal("accepted public socket")
	}
}
