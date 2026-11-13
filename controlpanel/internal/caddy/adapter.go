// Package caddy applies an auth-only JSON patch. Its caller owns the global
// installation lock, generation checks and durable auth.caddy/manifest updates.
package caddy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var ErrDrift = errors.New("Caddy configuration differs from prepared revision")
var ErrInput = errors.New("invalid or ambiguous managed Caddy authentication")

// Runtime must suppress configuration/credential values in diagnostics. Verify
// checks fresh candidate, wrong-password, canary and site/TLS connections.
type Runtime interface {
	Read(context.Context) ([]byte, error)
	Validate(context.Context, []byte) error
	Load(context.Context, []byte) error
}

type Prepared struct {
	Operation  string          `json:"operation"`
	Generation int64           `json:"generation"`
	Before     json.RawMessage `json:"before"`
	Candidate  json.RawMessage `json:"candidate"`
}

func canonical(raw []byte) ([]byte, error) {
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&value) != nil {
		return nil, ErrInput
	}
	// Reject trailing JSON or garbage.
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, ErrInput
	}
	return json.Marshal(value)
}

// PatchCreate requires exactly one forward_proxy handler and retains all
// other JSON properties, including unknown future directives and number values.
func PatchCreate(raw []byte, login, password string) ([]byte, error) {
	if login == "" || strings.ContainsAny(login, ":\r\n") || password == "" || strings.Contains(password, "{$") {
		return nil, ErrInput
	}
	normal, err := canonical(raw)
	if err != nil {
		return nil, err
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(normal))
	d.UseNumber()
	_ = d.Decode(&value)
	var handlers []map[string]any
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if x["handler"] == "forward_proxy" {
				handlers = append(handlers, x)
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(value)
	if len(handlers) != 1 {
		return nil, ErrInput
	}
	h := handlers[0]
	credentials, ok := h["auth_credentials"].([]any)
	if !ok || len(credentials) == 0 {
		return nil, ErrInput
	}
	for _, c := range credentials {
		encoded, ok := c.(string)
		if !ok {
			return nil, ErrInput
		}
		first, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, ErrInput
		}
		raw, err := base64.StdEncoding.DecodeString(string(first))
		if err != nil {
			return nil, ErrInput
		}
		name, _, ok := strings.Cut(string(raw), ":")
		clear(raw)
		clear(first)
		if !ok || name == login {
			return nil, ErrInput
		}
	}
	// forwardproxy stores base64 credentials as []byte, itself base64 in JSON.
	encoded := base64.StdEncoding.EncodeToString([]byte(login + ":" + password))
	h["auth_credentials"] = append(credentials, base64.StdEncoding.EncodeToString([]byte(encoded)))
	return json.Marshal(value)
}

func same(a, b []byte) bool {
	x, e := canonical(a)
	if e != nil {
		return false
	}
	defer clear(x)
	y, e := canonical(b)
	if e != nil {
		return false
	}
	defer clear(y)
	return bytes.Equal(x, y)
}

// ConfigEqual compares complete JSON configurations without dropping numbers
// or unknown directives; reused for startup/cutover drift inspection.
func ConfigEqual(a, b []byte) bool { return same(a, b) }

// Prepare persists before/candidate before any live mutation. The directory
// must already be private and on durable storage; it contains plaintext auth.
func Prepare(ctx context.Context, rt Runtime, directory, operation string, generation int64, login, password string) (*Prepared, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || operation == "" || generation < 1 {
		return nil, ErrInput
	}
	before, err := rt.Read(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(before)
	candidate, err := PatchCreate(before, login, password)
	if err != nil {
		return nil, err
	}
	defer clear(candidate)
	if err = rt.Validate(ctx, candidate); err != nil {
		return nil, err
	}
	p := &Prepared{operation, generation, append([]byte(nil), before...), append([]byte(nil), candidate...)}
	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	path := filepath.Join(directory, "prepared.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		dir, e := os.Open(directory)
		if e != nil {
			err = e
		} else {
			err = errors.Join(dir.Sync(), dir.Close())
		}
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func ReadPrepared(directory, operation string, generation int64) (*Prepared, error) {
	dir, err := os.Lstat(directory)
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return nil, ErrInput
	}
	path := filepath.Join(directory, "prepared.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrInput
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var p Prepared
	if json.Unmarshal(data, &p) != nil || p.Operation != operation || p.Generation != generation || !json.Valid(p.Before) || !json.Valid(p.Candidate) {
		return nil, ErrDrift
	}
	return &p, nil
}

// Apply never retries a load after an uncertain response. Recovery inspects
// exact candidate state before probing; rollback is separately gated.
func (p *Prepared) Apply(ctx context.Context, rt Runtime, verify func(context.Context) error) error {
	if verify == nil {
		return ErrInput
	}
	current, err := rt.Read(ctx)
	if err != nil {
		return err
	}
	defer clear(current)
	if !same(current, p.Before) {
		return ErrDrift
	}
	if err = rt.Load(ctx, p.Candidate); err != nil {
		return err
	}
	return p.Verify(ctx, rt, verify)
}

func (p *Prepared) Verify(ctx context.Context, rt Runtime, verify func(context.Context) error) error {
	if verify == nil {
		return ErrInput
	}
	current, err := rt.Read(ctx)
	if err != nil {
		return err
	}
	defer clear(current)
	if !same(current, p.Candidate) {
		return ErrDrift
	}
	if err = verify(ctx); err != nil {
		return err
	}
	current, err = rt.Read(ctx)
	if err != nil {
		return err
	}
	defer clear(current)
	if !same(current, p.Candidate) {
		return ErrDrift
	}
	return nil
}

func (p *Prepared) Rollback(ctx context.Context, rt Runtime, verifyOld func(context.Context) error) error {
	if verifyOld == nil {
		return ErrInput
	}
	current, err := rt.Read(ctx)
	if err != nil {
		return err
	}
	defer clear(current)
	if !same(current, p.Before) {
		if !same(current, p.Candidate) {
			return ErrDrift
		}
		if err = rt.Load(ctx, p.Before); err != nil {
			return err
		}
	}
	if err = verifyOld(ctx); err != nil {
		return err
	}
	current, err = rt.Read(ctx)
	if err != nil {
		return err
	}
	defer clear(current)
	if !same(current, p.Before) {
		return ErrDrift
	}
	return nil
}

func (p *Prepared) Clear()       { clear(p.Before); clear(p.Candidate) }
func (p *Prepared) Hash() string { return fmt.Sprintf("%x", sha256.Sum256(p.Candidate)) }
