package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// deviceTokenPrefix makes leaked tokens easy to recognise in logs and secret scanners.
const deviceTokenPrefix = "mrdd_"

// NewDeviceToken returns a fresh device token and the SHA-256 hash that is stored.
// The token itself is returned to the device once and never persisted server-side.
func NewDeviceToken() (token string, hash []byte) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw) // crypto/rand never fails on supported platforms
	token = deviceTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:]
}

// HashDeviceToken returns the stored form of token, or ok=false if it is not
// well-formed (wrong prefix or length), so malformed input never reaches the database.
func HashDeviceToken(token string) (hash []byte, ok bool) {
	body, found := strings.CutPrefix(token, deviceTokenPrefix)
	if !found || len(body) != base64.RawURLEncoding.EncodedLen(32) {
		return nil, false
	}
	if _, err := base64.RawURLEncoding.DecodeString(body); err != nil {
		return nil, false
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], true
}

// NewID returns a 128-bit random identifier as 32 lowercase hex characters.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	const hex = "0123456789abcdef"
	out := make([]byte, 32)
	for i, v := range b {
		out[i*2], out[i*2+1] = hex[v>>4], hex[v&0x0f]
	}
	return string(out)
}
