package vault

import (
	"bytes"
	"testing"
)

func TestCredentialBinding(t *testing.T) {
	v, err := New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{"user-id", 1, 2}
	secret := []byte("synthetic-fixture")
	n, c, err := v.Encrypt(b, secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := v.Decrypt(b, n, c)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatal("round trip failed")
	}
	other, _, err := v.Encrypt(b, secret)
	if err != nil || bytes.Equal(n, other) {
		t.Fatal("expected fresh nonce")
	}
	for _, changed := range []Binding{{"other", 1, 2}, {"user-id", 2, 2}, {"user-id", 1, 3}} {
		if _, err := v.Decrypt(changed, n, c); err == nil {
			t.Fatal("accepted changed binding")
		}
	}
	wrong, err := New(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Decrypt(b, n, c); err == nil {
		t.Fatal("accepted wrong key")
	}
	c[0] ^= 1
	if _, err := v.Decrypt(b, n, c); err == nil {
		t.Fatal("accepted modified credential")
	}
}

func TestInvalidInput(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("accepted short key")
	}
	v, err := New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []Binding{{"", 1, 1}, {"a", 0, 1}, {"a", 1, 0}} {
		if _, _, err := v.Encrypt(b, []byte("x")); err == nil {
			t.Fatal("accepted invalid binding")
		}
	}
	if _, _, err := v.Encrypt(Binding{"a", 1, 1}, nil); err == nil {
		t.Fatal("accepted empty password")
	}
}
