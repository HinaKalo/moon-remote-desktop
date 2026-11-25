// Package rsauth is the resource-server side of Moon SSO for moon-remote-server
// (ported from the Phase 0c spike, spikes/sso-dpop; see its REPORT.md):
// it authenticates API requests that carry a Moon SSO access token, either as
// a plain Bearer token or as a DPoP-bound token (RFC 9449).
//
// Access-token validation (JWKS discovery and caching, key rotation, typ,
// signature, iss, exp/nbf/iat, aud) is delegated to the official Go SDK
// (sso.moonl.cloud/sdk/go, Client.VerifyAccessToken). This package adds what
// the SDK does not have: a client allowlist, the DPoP proof check at the
// resource server (htm, htu, iat, jti replay, ath, cnf.jkt binding) and the
// HTTP plumbing (WWW-Authenticate challenges, request context).
package rsauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	moonsso "sso.moonl.cloud/sdk/go"
)

// Config configures a Verifier.
type Config struct {
	// SSO is a moonsso client for the issuer. Only its issuer and HTTP client
	// are used here (its ClientID is irrelevant because Audiences is always
	// passed explicitly).
	SSO *moonsso.Client

	// Audiences: a token is accepted when its aud contains at least one of
	// these. Moon SSO always puts the requesting client_id into aud and adds
	// the RFC 8707 resource when the authorization request carried one, so
	// list the moon-remote client ids and the resource URI. Required.
	Audiences []string

	// AllowedClients restricts the client_id claim. Empty allows any client
	// whose token passes the audience check.
	AllowedClients []string

	// PublicURL is the externally visible origin of this server (scheme and
	// host, e.g. "https://remote.moonl.cloud"). It is used to rebuild the
	// DPoP htu, so it must not be taken from the Host header behind a proxy.
	// Required.
	PublicURL string

	// RequireDPoP rejects unbound (plain Bearer) tokens. Moon SSO does not
	// issue DPoP-bound access tokens today (see REPORT.md), so this must stay
	// false until it does.
	RequireDPoP bool

	// ProofMaxAge bounds how old a proof's iat may be (default 60s), and
	// ProofSkew how far in the future (default 10s). Together they bound how
	// long a jti must be remembered.
	ProofMaxAge time.Duration
	ProofSkew   time.Duration

	// Replay remembers proof ids. Default: an in-process cache, which is only
	// correct for a single instance; use a shared store (Redis SET NX PX) when
	// running several replicas.
	Replay ReplayCache

	// Now is the clock for DPoP checks (tests).
	Now func() time.Time
}

// Verifier authenticates requests. It is safe for concurrent use.
type Verifier struct {
	cfg     Config
	baseURL *url.URL
}

// New validates cfg and returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	if cfg.SSO == nil {
		return nil, errors.New("rsauth: SSO client is required")
	}
	if len(cfg.Audiences) == 0 {
		return nil, errors.New("rsauth: at least one audience is required")
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("rsauth: PublicURL must be an origin like https://remote.moonl.cloud, got %q", cfg.PublicURL)
	}
	if cfg.ProofMaxAge <= 0 {
		cfg.ProofMaxAge = 60 * time.Second
	}
	if cfg.ProofSkew <= 0 {
		cfg.ProofSkew = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Replay == nil {
		rc := NewMemoryReplayCache(100_000)
		rc.now = cfg.Now
		cfg.Replay = rc
	}
	return &Verifier{cfg: cfg, baseURL: u}, nil
}

// Principal is the authenticated caller.
type Principal struct {
	Subject  string
	ClientID string
	Scopes   []string
	SID      string
	// JKT is the DPoP key thumbprint the token is bound to ("" for Bearer).
	JKT string
	// Scheme is "Bearer" or "DPoP".
	Scheme string
	Claims moonsso.Claims
}

// HasScope reports whether the token carries scope s.
func (p *Principal) HasScope(s string) bool { return slices.Contains(p.Scopes, s) }

// Error is an authentication failure, rendered as a 401 with a
// WWW-Authenticate challenge (RFC 6750 §3, RFC 9449 §7.1).
type Error struct {
	// Code is invalid_request, invalid_token or invalid_dpop_proof.
	Code        string
	Description string
	// DPoP selects the DPoP challenge scheme instead of Bearer.
	DPoP bool
}

func (e *Error) Error() string { return e.Code + ": " + e.Description }

func tokenErr(desc string) *Error { return &Error{Code: "invalid_token", Description: desc} }
func proofErr(desc string) *Error {
	return &Error{Code: "invalid_dpop_proof", Description: desc, DPoP: true}
}

// Authenticate checks the request's Authorization (and DPoP) headers.
func (v *Verifier) Authenticate(r *http.Request) (*Principal, *Error) {
	authz := r.Header.Values("Authorization")
	if len(authz) == 0 {
		return nil, &Error{Code: "", Description: "authentication required", DPoP: v.cfg.RequireDPoP}
	}
	if len(authz) > 1 {
		return nil, &Error{Code: "invalid_request", Description: "multiple Authorization headers"}
	}
	scheme, token, ok := strings.Cut(strings.TrimSpace(authz[0]), " ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		return nil, &Error{Code: "invalid_request", Description: "malformed Authorization header"}
	}
	isDPoP := strings.EqualFold(scheme, "DPoP")
	if !isDPoP && !strings.EqualFold(scheme, "Bearer") {
		return nil, &Error{Code: "invalid_request", Description: "unsupported authorization scheme"}
	}

	claims, err := v.cfg.SSO.VerifyAccessToken(r.Context(), token, v.cfg.Audiences...)
	if err != nil {
		return nil, &Error{Code: "invalid_token", Description: err.Error(), DPoP: isDPoP}
	}
	p := &Principal{
		Subject:  claims.Subject(),
		ClientID: claims.String("client_id"),
		Scopes:   strings.Fields(claims.String("scope")),
		SID:      claims.String("sid"),
		Claims:   claims,
	}
	if p.Subject == "" {
		return nil, tokenErr("token has no subject")
	}
	if len(v.cfg.AllowedClients) > 0 && !slices.Contains(v.cfg.AllowedClients, p.ClientID) {
		return nil, tokenErr("client not allowed")
	}

	boundJKT := cnfJKT(claims)
	switch {
	case boundJKT != "" && !isDPoP:
		// RFC 9449 §7.2: a DPoP-bound token presented as Bearer is invalid.
		return nil, &Error{Code: "invalid_token", Description: "DPoP-bound token sent with the Bearer scheme", DPoP: true}
	case boundJKT == "" && isDPoP:
		// RFC 9449 §7.1: the proof key must match the token's binding.
		return nil, &Error{Code: "invalid_token", Description: "token is not DPoP-bound", DPoP: true}
	case boundJKT == "" && v.cfg.RequireDPoP:
		return nil, &Error{Code: "invalid_token", Description: "DPoP-bound token required", DPoP: true}
	case boundJKT == "":
		p.Scheme = "Bearer"
		return p, nil
	}

	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return nil, proofErr("exactly one DPoP header is required")
	}
	jkt, perr := v.verifyProof(r.Context(), proofs[0], r.Method, v.htu(r), token)
	if perr != nil {
		return nil, perr
	}
	if jkt != boundJKT {
		return nil, proofErr("DPoP key does not match the token binding")
	}
	p.Scheme, p.JKT = "DPoP", jkt
	return p, nil
}

func cnfJKT(c moonsso.Claims) string {
	cnf, _ := c["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// htu is the request URI as the client addressed it: the configured public
// origin plus the request path, without query and fragment (RFC 9449 §4.3).
func (v *Verifier) htu(r *http.Request) string {
	u := *v.baseURL
	u.Path, u.RawPath = r.URL.Path, r.URL.RawPath
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// Middleware rejects unauthenticated requests with 401 and stores the
// Principal in the request context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, e := v.Authenticate(r)
		if e != nil {
			v.WriteError(w, e)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// WriteError renders e as a 401 with the matching WWW-Authenticate header.
func (v *Verifier) WriteError(w http.ResponseWriter, e *Error) {
	scheme := "Bearer"
	params := []string{`realm="` + v.baseURL.Host + `"`}
	if e.DPoP {
		scheme = "DPoP"
		params = append(params, `algs="`+strings.Join(proofAlgNames(), " ")+`"`)
	}
	if e.Code != "" {
		params = append(params, `error="`+e.Code+`"`, `error_description="`+sanitize(e.Description)+`"`)
	}
	w.Header().Set("WWW-Authenticate", scheme+" "+strings.Join(params, ", "))
	if !e.DPoP && !v.cfg.RequireDPoP && e.Code == "" {
		// Advertise both schemes on a bare 401.
		w.Header().Add("WWW-Authenticate", `DPoP algs="`+strings.Join(proofAlgNames(), " ")+`"`)
	}
	status := http.StatusUnauthorized
	if e.Code == "invalid_request" {
		status = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	code := e.Code
	if code == "" {
		code = "unauthorized"
	}
	_, _ = fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, code, e.Description)
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, s)
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated caller, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}
