// Package roster signs the list of an account's devices for LAN direct mode.
//
// While online, every device fetches its account's roster. A host in LAN mode only
// accepts controllers whose device key is in a roster signed by the server key it
// pinned at registration and not yet expired, so LAN mode keeps the account binding
// without contacting the server.
package roster

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Validity is how long a roster stays usable offline.
const Validity = 14 * 24 * time.Hour

// Entry is one device in the roster.
type Entry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	PublicKey string `json:"publicKey"` // base64 (std) Ed25519 key
}

// Roster is the signed payload. Field order is fixed by the struct, and clients verify
// the signature over the exact bytes they received, never over a re-encoding.
type Roster struct {
	Version   int     `json:"v"`
	UserSub   string  `json:"userSub"`
	IssuedAt  int64   `json:"iat"`
	ExpiresAt int64   `json:"exp"`
	Devices   []Entry `json:"devices"`
}

// Signed is what the API returns.
type Signed struct {
	Roster    string `json:"roster"`    // base64 (std) of the JSON bytes
	Signature string `json:"signature"` // base64 (std) Ed25519 signature over those bytes
	KeyID     string `json:"keyId"`
}

// Signer holds the server's roster key.
type Signer struct {
	key   ed25519.PrivateKey
	keyID string
}

// NewSigner wraps an Ed25519 private key.
func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key: key, keyID: KeyID(key.Public().(ed25519.PublicKey))}
}

// LoadSigner reads a base64 Ed25519 seed (32 bytes) from path.
func LoadSigner(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("roster key %s: want base64 of a %d-byte Ed25519 seed", path, ed25519.SeedSize)
	}
	return NewSigner(ed25519.NewKeyFromSeed(seed)), nil
}

// KeyID is the first 8 bytes of SHA-256 over the public key, hex encoded.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// PublicKey returns the verification key clients pin.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// KeyID returns the id of the signing key.
func (s *Signer) KeyID() string { return s.keyID }

// Sign builds and signs a roster valid from now for Validity.
func (s *Signer) Sign(userSub string, devices []Entry, now time.Time) (Signed, error) {
	if devices == nil {
		devices = []Entry{}
	}
	body, err := json.Marshal(Roster{
		Version: 1, UserSub: userSub, IssuedAt: now.Unix(), ExpiresAt: now.Add(Validity).Unix(), Devices: devices,
	})
	if err != nil {
		return Signed{}, err
	}
	return Signed{
		Roster:    base64.StdEncoding.EncodeToString(body),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, body)),
		KeyID:     s.keyID,
	}, nil
}

// Verify checks a Signed roster the way clients must: signature over the received
// bytes, then version and expiry. It exists for tests and as the reference for the
// Rust and TypeScript implementations.
func Verify(pub ed25519.PublicKey, sr Signed, now time.Time) (Roster, error) {
	body, err := base64.StdEncoding.DecodeString(sr.Roster)
	if err != nil {
		return Roster{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(sr.Signature)
	if err != nil {
		return Roster{}, err
	}
	if !ed25519.Verify(pub, body, sig) {
		return Roster{}, errors.New("roster: bad signature")
	}
	var r Roster
	if err := json.Unmarshal(body, &r); err != nil {
		return Roster{}, err
	}
	if r.Version != 1 {
		return Roster{}, fmt.Errorf("roster: unsupported version %d", r.Version)
	}
	if now.Unix() >= r.ExpiresAt {
		return Roster{}, errors.New("roster: expired")
	}
	return r, nil
}
