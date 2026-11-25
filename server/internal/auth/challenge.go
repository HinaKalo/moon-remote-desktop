package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Challenges hands out single-use nonces bound to one subject (a user or a device).
// A device signs the nonce with its private key to prove possession when it registers.
//
// Kept in memory: each environment runs one server process, and a restart only makes
// in-flight registrations retry.
type Challenges struct {
	TTL time.Duration
	// Max bounds memory use; Issue fails once this many unexpired nonces exist.
	Max int
	Now func() time.Time

	mu      sync.Mutex
	pending map[string]challenge
}

type challenge struct {
	subject string
	expires time.Time
}

// ErrTooManyChallenges is returned when Max unexpired nonces are outstanding.
var ErrTooManyChallenges = errors.New("auth: too many pending challenges")

func (c *Challenges) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Issue returns a new nonce for subject and when it expires.
func (c *Challenges) Issue(subject string) (nonce string, expires time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.pending == nil {
		c.pending = map[string]challenge{}
	}
	if len(c.pending) >= c.Max {
		for k, v := range c.pending {
			if !now.Before(v.expires) {
				delete(c.pending, k)
			}
		}
		if len(c.pending) >= c.Max {
			return "", time.Time{}, ErrTooManyChallenges
		}
	}
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	nonce = base64.RawURLEncoding.EncodeToString(raw)
	expires = now.Add(c.TTL)
	c.pending[nonce] = challenge{subject: subject, expires: expires}
	return nonce, expires, nil
}

// Consume reports whether nonce was issued to subject and is unexpired. A nonce is
// removed on first use, whether or not the check succeeds.
func (c *Challenges) Consume(subject, nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.pending[nonce]
	if !ok {
		return false
	}
	delete(c.pending, nonce)
	return ch.subject == subject && c.now().Before(ch.expires)
}
