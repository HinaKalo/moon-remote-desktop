// Package auth identifies the caller of every API request.
//
// Two kinds of caller exist:
//
//   - Users: a person signed in to sso.moonl.cloud (desktop app or web client). Their
//     access token is checked by a UserVerifier. The production verifier (JWT via the
//     issuer's JWKS plus DPoP proof) comes from the Phase 0c spike; until then only the
//     loopback-only DevVerifier exists.
//   - Devices: a registered installation calling with its own device token
//     ("Authorization: Device <token>"). The host service uses it so that a host stays
//     online with nobody signed in.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"moon-remote/server/internal/httpx"
	"moon-remote/server/internal/store"
)

// Principal is the authenticated caller.
type Principal struct {
	UserSub     string
	DisplayName string
	// DeviceID is set when the caller authenticated with a device token.
	DeviceID string
}

// IsDevice reports whether the caller is a device rather than a signed-in user.
func (p Principal) IsDevice() bool { return p.DeviceID != "" }

type ctxKey struct{}

// FromContext returns the caller set by the middleware.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// WithPrincipal stores p in ctx (used by the middleware and by tests).
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// VerifiedUser is what a UserVerifier extracts from a valid access token.
type VerifiedUser struct {
	Sub         string
	DisplayName string
}

// ErrUnauthenticated means the credentials were missing, malformed, expired or forged.
var ErrUnauthenticated = errors.New("auth: unauthenticated")

// ErrUnavailable means the verifier cannot currently check credentials (e.g. JWKS
// unreachable, or no verifier configured).
var ErrUnavailable = errors.New("auth: verifier unavailable")

// UserVerifier checks a user's access token. It receives the whole request because
// DPoP proofs bind the token to the HTTP method and URL.
type UserVerifier interface {
	VerifyUser(r *http.Request) (VerifiedUser, error)
}

// Unconfigured is the UserVerifier used when no SSO verification is set up: every
// user request fails with ErrUnavailable (503) instead of being let through.
type Unconfigured struct{}

func (Unconfigured) VerifyUser(*http.Request) (VerifiedUser, error) {
	return VerifiedUser{}, ErrUnavailable
}

// Authenticator turns request credentials into a Principal.
type Authenticator struct {
	Users UserVerifier
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
}

func (a *Authenticator) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Allow selects which caller kinds a route accepts.
type Allow int

const (
	AllowUser Allow = 1 << iota
	AllowDevice
	AllowAny = AllowUser | AllowDevice
)

// Require wraps h so it runs only for an authenticated caller of an allowed kind.
func (a *Authenticator) Require(allow Allow, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(r, allow)
		switch {
		case errors.Is(err, ErrUnavailable):
			httpx.WriteError(w, http.StatusServiceUnavailable, "auth_unavailable", "sign-in verification is temporarily unavailable")
			return
		case err != nil:
			w.Header().Set("WWW-Authenticate", `DPoP algs="ES256 EdDSA", Bearer, Device`)
			httpx.WriteError(w, http.StatusUnauthorized, "unauthenticated", "missing or invalid credentials")
			return
		}
		h.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// Authenticate resolves the caller without writing a response.
func (a *Authenticator) Authenticate(r *http.Request, allow Allow) (Principal, error) {
	scheme, cred, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	cred = strings.TrimSpace(cred)
	if cred == "" {
		return Principal{}, ErrUnauthenticated
	}
	if strings.EqualFold(scheme, "Device") {
		if allow&AllowDevice == 0 {
			return Principal{}, ErrUnauthenticated
		}
		return a.device(r.Context(), cred)
	}
	if allow&AllowUser == 0 {
		return Principal{}, ErrUnauthenticated
	}
	return a.user(r)
}

func (a *Authenticator) device(ctx context.Context, token string) (Principal, error) {
	hash, ok := HashDeviceToken(token)
	if !ok {
		return Principal{}, ErrUnauthenticated
	}
	d, err := a.Store.DeviceByTokenHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, errors.Join(ErrUnavailable, err)
	}
	u, err := a.Store.GetUser(ctx, d.UserSub)
	if err != nil {
		return Principal{}, errors.Join(ErrUnavailable, err)
	}
	return Principal{UserSub: d.UserSub, DisplayName: u.DisplayName, DeviceID: d.ID}, nil
}

func (a *Authenticator) user(r *http.Request) (Principal, error) {
	vu, err := a.Users.VerifyUser(r)
	if err != nil {
		if !errors.Is(err, ErrUnavailable) {
			err = ErrUnauthenticated
		}
		return Principal{}, err
	}
	now := a.now()
	if vu.DisplayName == "" {
		// The verifier could not learn a name (e.g. userinfo unreachable): keep the
		// stored one rather than overwriting it, and fall back to the subject.
		if u, err := a.Store.GetUser(r.Context(), vu.Sub); err == nil {
			vu.DisplayName = u.DisplayName
		} else {
			vu.DisplayName = vu.Sub
		}
	}
	if err := a.Store.UpsertUser(r.Context(), store.User{Sub: vu.Sub, DisplayName: vu.DisplayName, CreatedAt: now, UpdatedAt: now}); err != nil {
		if a.Log != nil {
			a.Log.Error("upsert user", "err", err)
		}
		return Principal{}, errors.Join(ErrUnavailable, err)
	}
	return Principal{UserSub: vu.Sub, DisplayName: vu.DisplayName}, nil
}
