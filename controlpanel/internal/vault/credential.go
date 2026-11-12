// Package vault encrypts one VPN credential for storage in the panel database.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const Algorithm = "AES-256-GCM"
const nonceSize = 12

// Binding identifies the database row and the key used for this ciphertext.
type Binding struct {
	UserID        string
	SecretVersion uint64
	KeyVersion    uint64
}

func (b Binding) additionalData() ([]byte, error) {
	if b.UserID == "" || len(b.UserID) > 255 || b.SecretVersion == 0 || b.KeyVersion == 0 {
		return nil, errors.New("invalid credential binding")
	}
	data := []byte("vpn-control/credential/v1\x00")
	data = append(data, byte(len(b.UserID)))
	data = append(data, b.UserID...)
	data = binary.BigEndian.AppendUint64(data, b.SecretVersion)
	return binary.BigEndian.AppendUint64(data, b.KeyVersion), nil
}

type Vault struct{ aead cipher.AEAD }

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("vault key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

func (v *Vault) Encrypt(b Binding, password []byte) (nonce, ciphertext []byte, err error) {
	aad, err := b.additionalData()
	if err != nil {
		return nil, nil, err
	}
	if len(password) == 0 || len(password) > 256 {
		return nil, nil, errors.New("invalid credential length")
	}
	// The standard library generates and prepends a fresh 96-bit nonce.
	sealed := v.aead.Seal(nil, nil, password, aad)
	return sealed[:nonceSize:nonceSize], sealed[nonceSize:], nil
}

func (v *Vault) Decrypt(b Binding, nonce, ciphertext []byte) ([]byte, error) {
	aad, err := b.additionalData()
	if err != nil {
		return nil, err
	}
	if len(nonce) != nonceSize || len(ciphertext) <= 16 || len(ciphertext) > 256+16 {
		return nil, errors.New("invalid stored credential")
	}
	stored := make([]byte, 0, len(nonce)+len(ciphertext))
	stored = append(stored, nonce...)
	stored = append(stored, ciphertext...)
	return v.aead.Open(nil, nil, stored, aad)
}
