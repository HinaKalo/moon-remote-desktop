package et

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Sealer encrypts EasyTier network secrets at rest with AES-256-GCM. The user subject
// is the additional data, so a sealed secret copied to another user's row fails to open.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer takes a 32-byte master key.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

// LoadSealer reads a base64 32-byte master key from path.
func LoadSealer(path string) (*Sealer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("master key %s: not base64", path)
	}
	return NewSealer(key)
}

// Seal returns nonce || ciphertext.
func (s *Sealer) Seal(plaintext []byte, userSub string) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return s.aead.Seal(nonce, nonce, plaintext, []byte(userSub))
}

// Open reverses Seal.
func (s *Sealer) Open(sealed []byte, userSub string) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed secret too short")
	}
	return s.aead.Open(nil, sealed[:n], sealed[n:], []byte(userSub))
}
