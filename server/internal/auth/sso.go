package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"

	"moon-remote/server/internal/rsauth"
)

// SSOVerifier authenticates users with sso.moonl.cloud access tokens.
//
// Token validation (JWKS, signature, iss, exp, aud, client allowlist, DPoP when the
// token is bound) is done by rsauth. Access tokens carry no display name, so it is
// fetched from the issuer's userinfo endpoint with the caller's own token and cached
// per subject.
type SSOVerifier struct {
	V   *rsauth.Verifier
	SSO *moonsso.Client
	// HTTP is used for userinfo; default has a 5 s timeout.
	HTTP *http.Client
	Now  func() time.Time

	mu    sync.Mutex
	names map[string]nameEntry
}

type nameEntry struct {
	name      string
	fresh     time.Time // reuse without asking until then
	nextRetry time.Time // after a failed lookup, do not ask again before then
}

const (
	nameTTL       = time.Hour
	nameRetry     = time.Minute
	maxNameCache  = 50_000
	maxUserinfoSz = 64 << 10
)

func (s *SSOVerifier) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// VerifyUser implements UserVerifier.
//
// Every validation failure is reported as ErrUnauthenticated: rsauth does not
// separate "issuer unreachable" from "bad token", and the SDK keeps serving a stale
// JWKS during an SSO outage, so only a cold start without the issuer is affected.
func (s *SSOVerifier) VerifyUser(r *http.Request) (VerifiedUser, error) {
	p, e := s.V.Authenticate(r)
	if e != nil {
		return VerifiedUser{}, ErrUnauthenticated
	}
	name := ""
	if p.Scheme == "Bearer" {
		// A DPoP-bound token cannot be replayed to userinfo without the client's key;
		// such callers keep their stored name.
		_, token, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		name = s.displayName(r.Context(), p.Subject, strings.TrimSpace(token))
	}
	return VerifiedUser{Sub: p.Subject, DisplayName: name}, nil
}

// displayName returns the cached name, refreshing it from userinfo when stale. It
// returns "" when no name is known; the Authenticator then keeps the stored one.
func (s *SSOVerifier) displayName(ctx context.Context, sub, token string) string {
	now := s.now()
	s.mu.Lock()
	e, ok := s.names[sub]
	s.mu.Unlock()
	if ok && (now.Before(e.fresh) || now.Before(e.nextRetry)) {
		return e.name
	}

	name, err := s.userinfo(ctx, sub, token)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.names == nil || len(s.names) >= maxNameCache {
		s.names = map[string]nameEntry{} // crude bound; names are cheap to refetch
	}
	if err != nil {
		e.nextRetry = now.Add(nameRetry)
		s.names[sub] = e // keep a stale name if we had one
		return e.name
	}
	s.names[sub] = nameEntry{name: name, fresh: now.Add(nameTTL)}
	return name
}

func (s *SSOVerifier) userinfo(ctx context.Context, sub, token string) (string, error) {
	d, err := s.SSO.Discover(ctx)
	if err != nil {
		return "", err
	}
	if d.UserinfoEndpoint == "" {
		return "", errors.New("issuer has no userinfo endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.UserinfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	hc := s.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", errors.New("userinfo: " + res.Status)
	}
	var info struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxUserinfoSz)).Decode(&info); err != nil {
		return "", err
	}
	if info.Sub != sub {
		return "", errors.New("userinfo: subject mismatch")
	}
	name := strings.TrimSpace(info.Name)
	if name == "" {
		name = strings.TrimSpace(info.PreferredUsername)
	}
	if len(name) > 255 {
		name = name[:255]
	}
	return name, nil
}

// ByScheme routes "Dev" credentials to Dev and everything else to Other. It lets a
// local dev server accept both the Dev shortcut and real tokens from the SSO testbed.
type ByScheme struct {
	Dev   UserVerifier
	Other UserVerifier
}

func (b ByScheme) VerifyUser(r *http.Request) (VerifiedUser, error) {
	scheme, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if strings.EqualFold(scheme, "Dev") && b.Dev != nil {
		return b.Dev.VerifyUser(r)
	}
	if b.Other == nil {
		return VerifiedUser{}, ErrUnavailable
	}
	return b.Other.VerifyUser(r)
}
