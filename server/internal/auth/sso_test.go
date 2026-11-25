package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	moonsso "sso.moonl.cloud/sdk/go"

	"moon-remote/server/internal/rsauth"
	"moon-remote/server/internal/store"
)

const (
	testPublicURL = "https://remote.moonl.cloud"
	desktopClient = "ms_desktop"
	webClient     = "ms_web"
)

// fakeIssuer serves discovery, JWKS and userinfo, and mints ES256 access tokens.
type fakeIssuer struct {
	srv  *httptest.Server
	key  *ecdsa.PrivateKey
	mu   sync.Mutex
	name map[string]string // sub -> name served by userinfo
	down atomic.Bool       // userinfo answers 503
	hits atomic.Int32      // userinfo requests
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &fakeIssuer{key: k, name: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/jwks", "userinfo_endpoint": f.srv.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		// A real issuer validates the token; here the sub is read back from it.
		_, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		jws, err := jose.ParseSignedCompact(tok, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var cl map[string]any
		_ = json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &cl)
		sub, _ := cl["sub"].(string)
		f.mu.Lock()
		name := f.name[sub]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": sub, "name": name, "preferred_username": "user_" + sub})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) setName(sub, name string) {
	f.mu.Lock()
	f.name[sub] = name
	f.mu.Unlock()
}

func (f *fakeIssuer) mint(t *testing.T, sub, clientID string) string {
	t.Helper()
	now := time.Now()
	payload, _ := json.Marshal(map[string]any{
		"iss": f.srv.URL, "sub": sub, "aud": []string{clientID}, "client_id": clientID,
		"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "jti": "j" + sub + clientID, "scope": "openid profile",
	})
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: f.key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	jws, _ := s.Sign(payload)
	out, _ := jws.CompactSerialize()
	return out
}

func newSSOVerifier(t *testing.T, f *fakeIssuer, now *time.Time) *SSOVerifier {
	t.Helper()
	sso, err := moonsso.NewClient(moonsso.Config{Issuer: f.srv.URL, ClientID: "moon-remote-server"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := rsauth.New(rsauth.Config{
		SSO: sso, Audiences: []string{desktopClient, webClient, testPublicURL},
		AllowedClients: []string{desktopClient, webClient}, PublicURL: testPublicURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &SSOVerifier{V: v, SSO: sso, Now: func() time.Time { return *now }}
}

func bearer(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/devices", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestSSOVerifierAcceptsAllowedClients(t *testing.T) {
	f := newFakeIssuer(t)
	f.setName("u1", "Alice")
	now := time.Now()
	v := newSSOVerifier(t, f, &now)
	for _, client := range []string{desktopClient, webClient} {
		vu, err := v.VerifyUser(bearer(f.mint(t, "u1", client)))
		if err != nil || vu.Sub != "u1" || vu.DisplayName != "Alice" {
			t.Fatalf("%s: %+v %v", client, vu, err)
		}
	}
	if f.hits.Load() != 1 {
		t.Fatalf("userinfo must be cached per subject, got %d calls", f.hits.Load())
	}
}

func TestSSOVerifierRejects(t *testing.T) {
	f := newFakeIssuer(t)
	now := time.Now()
	v := newSSOVerifier(t, f, &now)
	good := f.mint(t, "u1", desktopClient)
	for name, r := range map[string]*http.Request{
		"other client":   bearer(f.mint(t, "u1", "ms_someone_else")),
		"tampered":       bearer(good[:len(good)-4] + "AAAA"),
		"garbage":        bearer("not-a-jwt"),
		"unbound DPoP":   func() *http.Request { r := bearer(good); r.Header.Set("Authorization", "DPoP "+good); return r }(),
		"no credentials": httptest.NewRequest("GET", "/", nil),
	} {
		if _, err := v.VerifyUser(r); err != ErrUnauthenticated {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSSOVerifierNameRefreshAndOutage(t *testing.T) {
	f := newFakeIssuer(t)
	f.setName("u1", "Alice")
	now := time.Now()
	v := newSSOVerifier(t, f, &now)
	tok := f.mint(t, "u1", webClient)

	if vu, _ := v.VerifyUser(bearer(tok)); vu.DisplayName != "Alice" {
		t.Fatalf("first: %q", vu.DisplayName)
	}
	// After the TTL a rename is picked up.
	f.setName("u1", "Alice Liddell")
	now = now.Add(nameTTL + time.Second)
	if vu, _ := v.VerifyUser(bearer(tok)); vu.DisplayName != "Alice Liddell" {
		t.Fatalf("refresh: %q", vu.DisplayName)
	}
	// Userinfo down: keep the stale name, and back off instead of asking every request.
	f.down.Store(true)
	now = now.Add(nameTTL + time.Second)
	before := f.hits.Load()
	for range 5 {
		if vu, err := v.VerifyUser(bearer(tok)); err != nil || vu.DisplayName != "Alice Liddell" {
			t.Fatalf("outage: %+v %v", vu, err)
		}
	}
	if got := f.hits.Load() - before; got != 1 {
		t.Fatalf("want one userinfo attempt during back-off, got %d", got)
	}
	// Falls back to preferred_username when name is empty.
	f.down.Store(false)
	tok2 := f.mint(t, "u2", webClient)
	if vu, _ := v.VerifyUser(bearer(tok2)); vu.DisplayName != "user_u2" {
		t.Fatalf("preferred_username fallback: %q", vu.DisplayName)
	}
}

func TestAuthenticatorKeepsStoredNameWhenUnknown(t *testing.T) {
	f := newFakeIssuer(t)
	f.down.Store(true) // no names available at all
	now := time.Now()
	st := store.NewMemory()
	_ = st.UpsertUser(context.Background(), store.User{Sub: "u1", DisplayName: "Stored Name", CreatedAt: now, UpdatedAt: now})
	a := &Authenticator{Users: newSSOVerifier(t, f, &now), Store: st}

	p, err := a.Authenticate(bearer(f.mint(t, "u1", desktopClient)), AllowUser)
	if err != nil || p.DisplayName != "Stored Name" {
		t.Fatalf("stored name not kept: %+v %v", p, err)
	}
	p, err = a.Authenticate(bearer(f.mint(t, "new-user", desktopClient)), AllowUser)
	if err != nil || p.DisplayName != "new-user" {
		t.Fatalf("new user without name: %+v %v", p, err)
	}
}

func TestByScheme(t *testing.T) {
	b := ByScheme{Dev: DevVerifier{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("Authorization", "Dev alice")
	if vu, err := b.VerifyUser(r); err != nil || vu.Sub != "dev|alice" {
		t.Fatalf("dev route: %+v %v", vu, err)
	}
	r.Header.Set("Authorization", "Bearer x")
	if _, err := b.VerifyUser(r); err != ErrUnavailable {
		t.Fatalf("no other verifier: %v", err)
	}
}
