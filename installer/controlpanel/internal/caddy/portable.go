package caddy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type AuthCredential struct{ Login, Password string }

func PreparePortableAuth(ctx context.Context, rt Runtime, directory, operation string, generation int64, users []AuthCredential) (*Prepared, error) {
	return prepareRendered(ctx, rt, directory, operation, generation, func(raw []byte) ([]byte, error) {
		var value any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if d.Decode(&value) != nil {
			return nil, ErrInput
		}
		seen := map[string]bool{}
		var auth []string
		for _, u := range users {
			if u.Login == "" || u.Password == "" || seen[u.Login] {
				return nil, ErrInput
			}
			seen[u.Login] = true
			auth = append(auth, base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(u.Login+":"+u.Password)))))
		}
		if !seen["master_user"] {
			return nil, ErrInput
		}
		count := 0
		var walk func(any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				if x["handler"] == "forward_proxy" {
					count++
					x["auth_credentials"] = auth
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
		if count != 1 {
			return nil, ErrInput
		}
		return json.Marshal(value)
	}, nil)
}

func VerifyPortableHash(ctx context.Context, rt Runtime, expected string) error {
	raw, e := rt.Read(ctx)
	if e != nil {
		return e
	}
	defer clear(raw)
	value, e := canonical(raw)
	if e != nil {
		return e
	}
	defer clear(value)
	if fmt.Sprintf("%x", sha256.Sum256(value)) != expected {
		return ErrDrift
	}
	return nil
}
