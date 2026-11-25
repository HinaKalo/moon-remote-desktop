// Package support issues and redeems single-use 12-digit remote support codes.
//
// A host user calls POST /v1/support/codes to get a 12-digit code valid for 5 minutes.
// Any authenticated SSO user (including another account) may call POST /v1/support/redeem
// once to obtain the session ID and host identity; the code is immediately consumed and
// cannot be reused. Session authentication still runs SPAKE2 with the support code as
// secret, followed by explicit host-user consent.
package support

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/httpx"
)

const (
	DefaultTTL = 5 * time.Minute
	MaxActive  = 10_000
)

type entry struct {
	session  string
	hostSub  string
	hostName string
	expires  time.Time
}

// API manages in-memory single-use support codes.
type API struct {
	Auth *auth.Authenticator
	TTL  time.Duration
	Now  func() time.Time

	mu    sync.Mutex
	codes map[string]entry
}

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *API) ttl() time.Duration {
	if a.TTL > 0 {
		return a.TTL
	}
	return DefaultTTL
}

// Register adds POST /v1/support/codes and POST /v1/support/redeem.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/support/codes", a.Auth.Require(auth.AllowUser, http.HandlerFunc(a.create)))
	mux.Handle("POST /v1/support/redeem", a.Auth.Require(auth.AllowUser, http.HandlerFunc(a.redeem)))
}

func randomDigits12() (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	s := n.String()
	return strings.Repeat("0", 12-len(s)) + s, nil
}

func randomSessionID() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return "sup_" + base64.RawURLEncoding.EncodeToString(b)
}

func (a *API) create(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	now := a.now()
	exp := now.Add(a.ttl())

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.codes == nil {
		a.codes = make(map[string]entry)
	}
	if len(a.codes) >= MaxActive {
		for k, v := range a.codes {
			if !now.Before(v.expires) {
				delete(a.codes, k)
			}
		}
	}
	if len(a.codes) >= MaxActive {
		httpx.WriteError(w, http.StatusTooManyRequests, "busy", "too many active support codes")
		return
	}

	var code string
	for range 8 {
		c, err := randomDigits12()
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "internal", "could not generate code")
			return
		}
		if _, exists := a.codes[c]; !exists {
			code = c
			break
		}
	}
	if code == "" {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", "could not allocate code")
		return
	}

	session := randomSessionID()
	name := p.DisplayName
	if name == "" {
		name = p.UserSub
	}
	a.codes[code] = entry{session: session, hostSub: p.UserSub, hostName: name, expires: exp}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"code":      code,
		"session":   session,
		"expiresAt": exp.UTC(),
	})
}

func (a *API) redeem(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, req.Code)
	if len(digits) != 12 {
		httpx.WriteError(w, http.StatusBadRequest, "bad_code", "support code must be 12 digits")
		return
	}

	now := a.now()
	a.mu.Lock()
	e, ok := a.codes[digits]
	if ok {
		delete(a.codes, digits) // single-use: consumed on first attempt
	}
	a.mu.Unlock()

	if !ok || !now.Before(e.expires) {
		httpx.WriteError(w, http.StatusNotFound, "invalid_code", "support code is unknown, expired, or already used")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"session":  e.session,
		"hostSub":  e.hostSub,
		"hostName": e.hostName,
	})
}
