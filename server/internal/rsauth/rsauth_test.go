package rsauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
)

const (
	publicURL = "https://remote.moonl.cloud"
	resource  = "https://remote.moonl.cloud"
	desktopID = "moon-remote-desktop"
	webID     = "moon-remote-web"
)

// ---- fake issuer -----------------------------------------------------------

type signingKey struct {
	kid  string
	priv *ecdsa.PrivateKey
}

func newSigningKey(t *testing.T, kid string) *signingKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{kid: kid, priv: k}
}

type issuer struct {
	srv        *httptest.Server
	mu         sync.Mutex
	published  []*signingKey
	jwksHits   atomic.Int32
	discovered atomic.Int32
}

func newIssuer(t *testing.T, keys ...*signingKey) *issuer {
	t.Helper()
	is := &issuer{published: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		is.discovered.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   is.srv.URL,
			"jwks_uri": is.srv.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		is.jwksHits.Add(1)
		is.mu.Lock()
		defer is.mu.Unlock()
		set := jose.JSONWebKeySet{}
		for _, k := range is.published {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: "ES256", Use: "sig"})
		}
		_ = json.NewEncoder(w).Encode(set)
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) publish(keys ...*signingKey) {
	is.mu.Lock()
	is.published = keys
	is.mu.Unlock()
}

type tokenOpts struct {
	iss, sub, clientID, typ, jkt string
	aud                          []string
	exp, nbf                     time.Time
}

func mint(t *testing.T, k *signingKey, o tokenOpts) string {
	t.Helper()
	now := time.Now()
	cl := map[string]any{
		"iss": o.iss, "sub": o.sub, "aud": o.aud, "client_id": o.clientID,
		"exp": o.exp.Unix(), "iat": now.Unix(), "nbf": o.nbf.Unix(), "jti": "at-" + randID(t), "scope": "openid profile",
	}
	if o.jkt != "" {
		cl["cnf"] = map[string]string{"jkt": o.jkt}
	}
	payload, _ := json.Marshal(cl)
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(o.typ)).WithHeader("kid", k.kid)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func randID(t *testing.T) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- DPoP client side --------------------------------------------------------

type dpopKey struct{ priv *ecdsa.PrivateKey }

func newDPoPKey(t *testing.T) *dpopKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &dpopKey{k}
}

func (d *dpopKey) jkt(t *testing.T) string {
	tp, err := (&jose.JSONWebKey{Key: &d.priv.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

type proofOpts struct {
	htm, htu, jti, ath, typ string
	iat                     time.Time
	noIat                   bool
	signWith                *ecdsa.PrivateKey // sign with a different key than the embedded JWK
}

func (d *dpopKey) proof(t *testing.T, o proofOpts) string {
	t.Helper()
	cl := map[string]any{"htm": o.htm, "htu": o.htu, "jti": o.jti, "ath": o.ath}
	if !o.noIat {
		cl["iat"] = o.iat.Unix()
	}
	payload, _ := json.Marshal(cl)
	typ := o.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	signer := d.priv
	if o.signWith != nil {
		signer = o.signWith
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("jwk", jose.JSONWebKey{Key: &d.priv.PublicKey})
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: signer}, opts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := jws.CompactSerialize()
	return out
}

func ath(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

// ---- harness -----------------------------------------------------------------

type env struct {
	t   *testing.T
	is  *issuer
	key *signingKey
	v   *Verifier
	now time.Time
}

func newEnv(t *testing.T, mut ...func(*Config)) *env {
	t.Helper()
	key := newSigningKey(t, "k1")
	is := newIssuer(t, key)
	sso, err := moonsso.NewClient(moonsso.Config{Issuer: is.srv.URL, ClientID: "moon-remote-server"})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, is: is, key: key, now: time.Now()}
	cfg := Config{
		SSO: sso, Audiences: []string{desktopID, webID, resource}, AllowedClients: []string{desktopID, webID},
		PublicURL: publicURL, Now: func() time.Time { return e.now },
	}
	for _, m := range mut {
		m(&cfg)
	}
	if e.v, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) token(mut ...func(*tokenOpts)) string {
	o := tokenOpts{iss: e.is.srv.URL, sub: "user-1", clientID: desktopID, typ: "at+jwt", aud: []string{desktopID},
		exp: time.Now().Add(10 * time.Minute), nbf: time.Now().Add(-5 * time.Second)}
	for _, m := range mut {
		m(&o)
	}
	return mint(e.t, e.key, o)
}

const apiPath = "/api/v1/hosts"

func (e *env) do(authz string, headers map[string]string) (*httptest.ResponseRecorder, *Principal) {
	req := httptest.NewRequest(http.MethodGet, "http://10.0.0.5:8080"+apiPath+"?page=2", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	var got *Principal
	rec := httptest.NewRecorder()
	e.v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = PrincipalFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	return rec, got
}

func expect401(t *testing.T, rec *httptest.ResponseRecorder, wantErr, wantDesc string) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body)
	}
	h := rec.Header().Get("WWW-Authenticate")
	if wantErr != "" && !strings.Contains(h, `error="`+wantErr+`"`) {
		t.Fatalf("WWW-Authenticate = %q, want error %q", h, wantErr)
	}
	if wantDesc != "" && !strings.Contains(rec.Body.String(), wantDesc) {
		t.Fatalf("body = %s, want %q", rec.Body, wantDesc)
	}
}

// ---- access token validation ---------------------------------------------------

func TestBearerAccepted(t *testing.T) {
	e := newEnv(t)
	rec, p := e.do("Bearer "+e.token(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if p.Subject != "user-1" || p.ClientID != desktopID || p.Scheme != "Bearer" || p.JKT != "" || !p.HasScope("profile") {
		t.Fatalf("principal = %+v", p)
	}
}

func TestResourceAudienceAccepted(t *testing.T) {
	e := newEnv(t)
	rec, _ := e.do("Bearer "+e.token(func(o *tokenOpts) { o.clientID, o.aud = webID, []string{webID, resource} }), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestTokenRejections(t *testing.T) {
	e := newEnv(t)
	other := newSigningKey(t, "k1") // same kid, different key: forged signature
	cases := []struct {
		name, tok, desc string
	}{
		{"expired", e.token(func(o *tokenOpts) { o.exp = time.Now().Add(-2 * time.Minute) }), "expired"},
		{"not yet valid", e.token(func(o *tokenOpts) { o.nbf = time.Now().Add(5 * time.Minute) }), "not yet valid"},
		{"wrong issuer", e.token(func(o *tokenOpts) { o.iss = "https://evil.example" }), "issuer mismatch"},
		{"wrong audience", e.token(func(o *tokenOpts) { o.aud = []string{"some-other-app"} }), "audience mismatch"},
		{"client not allowed", e.token(func(o *tokenOpts) { o.clientID, o.aud = "some-other-app", []string{"some-other-app", resource} }), "client not allowed"},
		{"id token typ", e.token(func(o *tokenOpts) { o.typ = "JWT" }), "unexpected token type"},
		{"wrong signing key", mint(t, other, tokenOpts{iss: e.is.srv.URL, sub: "u", clientID: desktopID, typ: "at+jwt", aud: []string{desktopID}, exp: time.Now().Add(time.Minute), nbf: time.Now()}), "invalid token signature"},
		{"garbage", "not.a.jwt", "malformed"},
		{"empty subject", e.token(func(o *tokenOpts) { o.sub = "" }), "no subject"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, _ := e.do("Bearer "+c.tok, nil)
			expect401(t, rec, "invalid_token", c.desc)
		})
	}
}

func TestMissingAndMalformedAuthorization(t *testing.T) {
	e := newEnv(t)
	rec, _ := e.do("", nil)
	expect401(t, rec, "", "")
	if got := rec.Header().Values("WWW-Authenticate"); len(got) != 2 || !strings.HasPrefix(got[0], "Bearer ") || !strings.HasPrefix(got[1], "DPoP ") {
		t.Fatalf("challenges = %q", got)
	}
	for _, h := range []string{"Basic abc", "Bearer", "Bearer   "} {
		rec, _ := e.do(h, nil)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: status %d", h, rec.Code)
		}
	}
}

func TestUnknownKidRejectedAndRateLimited(t *testing.T) {
	e := newEnv(t)
	if rec, _ := e.do("Bearer "+e.token(), nil); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body)
	}
	stranger := newSigningKey(t, "k-unknown")
	tok := mint(t, stranger, tokenOpts{iss: e.is.srv.URL, sub: "u", clientID: desktopID, typ: "at+jwt", aud: []string{desktopID}, exp: time.Now().Add(time.Minute), nbf: time.Now()})
	rec, _ := e.do("Bearer "+tok, nil)
	expect401(t, rec, "invalid_token", "unknown signing key")
	hits := e.is.jwksHits.Load()
	if hits != 2 {
		t.Fatalf("JWKS fetched %d times, want 2 (initial + one forced refresh)", hits)
	}
	// A flood of unknown kids must not hammer the issuer (refetch at most every 30s).
	for range 5 {
		e.do("Bearer "+tok, nil)
	}
	if e.is.jwksHits.Load() != hits {
		t.Fatalf("JWKS refetched during the 30s backoff: %d", e.is.jwksHits.Load())
	}
}

func TestJWKSCachedAndKeyRotation(t *testing.T) {
	e := newEnv(t)
	for range 20 {
		if rec, _ := e.do("Bearer "+e.token(), nil); rec.Code != http.StatusNoContent {
			t.Fatal(rec.Body)
		}
	}
	if e.is.jwksHits.Load() != 1 || e.is.discovered.Load() != 1 {
		t.Fatalf("jwks hits %d, discovery hits %d; want 1 and 1", e.is.jwksHits.Load(), e.is.discovered.Load())
	}
	// Issuer rotates: publishes k2 next to k1 and starts signing with k2.
	k2 := newSigningKey(t, "k2")
	e.is.publish(e.key, k2)
	old := e.key
	e.key = k2
	if rec, _ := e.do("Bearer "+e.token(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("token signed with rotated key rejected: %s", rec.Body)
	}
	if e.is.jwksHits.Load() != 2 {
		t.Fatalf("rotation should trigger exactly one JWKS refetch, got %d hits", e.is.jwksHits.Load())
	}
	// Tokens from the previous key stay valid while it is still published.
	e.key = old
	if rec, _ := e.do("Bearer "+e.token(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("token signed with previous key rejected: %s", rec.Body)
	}
}

// ---- DPoP ---------------------------------------------------------------------

type dpopCase struct {
	e   *env
	key *dpopKey
	tok string
}

func newDPoPCase(t *testing.T, mut ...func(*Config)) *dpopCase {
	e := newEnv(t, mut...)
	k := newDPoPKey(t)
	return &dpopCase{e: e, key: k, tok: e.token(func(o *tokenOpts) { o.jkt = k.jkt(t) })}
}

func (d *dpopCase) good() proofOpts {
	return proofOpts{htm: http.MethodGet, htu: publicURL + apiPath, jti: randID(d.e.t), ath: ath(d.tok), iat: d.e.now}
}

func (d *dpopCase) send(o proofOpts) *httptest.ResponseRecorder {
	rec, _ := d.e.do("DPoP "+d.tok, map[string]string{"DPoP": d.key.proof(d.e.t, o)})
	return rec
}

func TestDPoPBoundTokenAccepted(t *testing.T) {
	d := newDPoPCase(t)
	rec, p := d.e.do("DPoP "+d.tok, map[string]string{"DPoP": d.key.proof(t, d.good())})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if p.Scheme != "DPoP" || p.JKT != d.key.jkt(t) {
		t.Fatalf("principal = %+v", p)
	}
	// htu normalization: scheme/host case and default port do not matter, query is ignored.
	o := d.good()
	o.htu = "HTTPS://Remote.MoonL.cloud:443" + apiPath + "?page=2"
	if rec := d.send(o); rec.Code != http.StatusNoContent {
		t.Fatalf("normalized htu rejected: %s", rec.Body)
	}
}

func TestDPoPReplayRejected(t *testing.T) {
	d := newDPoPCase(t)
	proof := d.key.proof(t, d.good())
	hdr := map[string]string{"DPoP": proof}
	if rec, _ := d.e.do("DPoP "+d.tok, hdr); rec.Code != http.StatusNoContent {
		t.Fatalf("first use: %s", rec.Body)
	}
	rec, _ := d.e.do("DPoP "+d.tok, hdr)
	expect401(t, rec, "invalid_dpop_proof", "replayed")
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "DPoP ") {
		t.Fatalf("challenge = %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestDPoPReplayWindowExpires(t *testing.T) {
	d := newDPoPCase(t)
	o := d.good()
	if rec := d.send(o); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Body)
	}
	// Once the proof is too old to pass the iat check the jti may be forgotten;
	// the same proof is then rejected for its age, not accepted.
	d.e.now = d.e.now.Add(2 * time.Minute)
	rec := d.send(o)
	expect401(t, rec, "invalid_dpop_proof", "iat outside")
}

func TestDPoPRejections(t *testing.T) {
	d := newDPoPCase(t)
	attacker := newDPoPKey(t)
	cases := []struct {
		name string
		mut  func(*proofOpts)
		key  *dpopKey
		desc string
	}{
		{"wrong key (not the bound jkt)", nil, attacker, "does not match the token binding"},
		{"signature by another key than the embedded jwk", func(o *proofOpts) { o.signWith = attacker.priv }, nil, "invalid DPoP signature"},
		{"wrong htm", func(o *proofOpts) { o.htm = http.MethodPost }, nil, "htm mismatch"},
		{"wrong htu path", func(o *proofOpts) { o.htu = publicURL + "/api/v1/other" }, nil, "htu mismatch"},
		{"wrong htu host", func(o *proofOpts) { o.htu = "https://evil.example" + apiPath }, nil, "htu mismatch"},
		{"internal host instead of public URL", func(o *proofOpts) { o.htu = "http://10.0.0.5:8080" + apiPath }, nil, "htu mismatch"},
		{"stale iat", func(o *proofOpts) { o.iat = d.e.now.Add(-2 * time.Minute) }, nil, "iat outside"},
		{"future iat", func(o *proofOpts) { o.iat = d.e.now.Add(time.Minute) }, nil, "iat outside"},
		{"missing iat", func(o *proofOpts) { o.noIat = true }, nil, "iat missing"},
		{"missing jti", func(o *proofOpts) { o.jti = "" }, nil, "jti missing"},
		{"ath of another token", func(o *proofOpts) { o.ath = ath("other-token") }, nil, "ath does not match"},
		{"missing ath", func(o *proofOpts) { o.ath = "" }, nil, "ath does not match"},
		{"wrong typ", func(o *proofOpts) { o.typ = "JWT" }, nil, "typ must be dpop+jwt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := d.good()
			if c.mut != nil {
				c.mut(&o)
			}
			k := d.key
			if c.key != nil {
				k = c.key
			}
			rec, _ := d.e.do("DPoP "+d.tok, map[string]string{"DPoP": k.proof(t, o)})
			expect401(t, rec, "invalid_dpop_proof", c.desc)
		})
	}
}

func TestDPoPHeaderProblems(t *testing.T) {
	d := newDPoPCase(t)
	// No proof at all.
	rec, _ := d.e.do("DPoP "+d.tok, nil)
	expect401(t, rec, "invalid_dpop_proof", "exactly one DPoP header")
	// Two proofs.
	req := httptest.NewRequest(http.MethodGet, publicURL+apiPath, nil)
	req.Header.Set("Authorization", "DPoP "+d.tok)
	req.Header.Add("DPoP", d.key.proof(t, d.good()))
	req.Header.Add("DPoP", d.key.proof(t, d.good()))
	rr := httptest.NewRecorder()
	d.e.v.Middleware(http.NotFoundHandler()).ServeHTTP(rr, req)
	expect401(t, rr, "invalid_dpop_proof", "exactly one DPoP header")
	// alg=none / HS256 proofs are refused by the algorithm allowlist.
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","alg":"none"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"htm":"GET"}`)) + "."
	rec, _ = d.e.do("DPoP "+d.tok, map[string]string{"DPoP": unsigned})
	expect401(t, rec, "invalid_dpop_proof", "malformed DPoP proof")
}

func TestBoundTokenAsBearerRejected(t *testing.T) {
	d := newDPoPCase(t)
	// A stolen bound token must not work without the key, even with the Bearer scheme.
	rec, _ := d.e.do("Bearer "+d.tok, nil)
	expect401(t, rec, "invalid_token", "DPoP-bound token sent with the Bearer scheme")
	// And a proof from the right key does not rescue the Bearer scheme either.
	rec, _ = d.e.do("Bearer "+d.tok, map[string]string{"DPoP": d.key.proof(t, d.good())})
	expect401(t, rec, "invalid_token", "Bearer scheme")
}

func TestUnboundTokenWithDPoPSchemeRejected(t *testing.T) {
	e := newEnv(t)
	k := newDPoPKey(t)
	tok := e.token()
	o := proofOpts{htm: http.MethodGet, htu: publicURL + apiPath, jti: randID(t), ath: ath(tok), iat: e.now}
	rec, _ := e.do("DPoP "+tok, map[string]string{"DPoP": k.proof(t, o)})
	expect401(t, rec, "invalid_token", "not DPoP-bound")
}

func TestRequireDPoP(t *testing.T) {
	d := newDPoPCase(t, func(c *Config) { c.RequireDPoP = true })
	rec, _ := d.e.do("Bearer "+d.e.token(), nil)
	expect401(t, rec, "invalid_token", "DPoP-bound token required")
	if rec := d.send(d.good()); rec.Code != http.StatusNoContent {
		t.Fatalf("bound token rejected under RequireDPoP: %s", rec.Body)
	}
}

func TestReplayCacheBoundedFailsClosed(t *testing.T) {
	c := NewMemoryReplayCache(2)
	now := time.Now()
	c.now = func() time.Time { return now }
	ctx := context.Background()
	if !c.Add(ctx, "a", now.Add(time.Minute)) || !c.Add(ctx, "b", now.Add(time.Second)) {
		t.Fatal("fresh keys rejected")
	}
	if c.Add(ctx, "c", now.Add(time.Minute)) {
		t.Fatal("full cache with live entries must fail closed")
	}
	now = now.Add(2 * time.Second) // "b" expired
	if !c.Add(ctx, "c", now.Add(time.Minute)) {
		t.Fatal("expired entry not evicted")
	}
	if c.Add(ctx, "a", now.Add(time.Minute)) {
		t.Fatal("live key accepted twice")
	}
}

func TestMiddleware(t *testing.T) {
	e := newEnv(t)
	h := e.v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(PrincipalFrom(r.Context()).Subject))
	}))
	req := httptest.NewRequest(http.MethodGet, apiPath, nil)
	req.Header.Set("Authorization", "Bearer "+e.token())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "user-1" {
		t.Fatalf("middleware: %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest(http.MethodGet, apiPath, nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("middleware unauthenticated: %d", rec.Code)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	sso, _ := moonsso.NewClient(moonsso.Config{Issuer: "https://sso.moonl.cloud", ClientID: "x"})
	for _, u := range []string{"", "remote.moonl.cloud", "https://remote.moonl.cloud/api", "ftp://x"} {
		if _, err := New(Config{SSO: sso, Audiences: []string{"x"}, PublicURL: u}); err == nil {
			t.Fatalf("PublicURL %q accepted", u)
		}
	}
	if _, err := New(Config{SSO: sso, PublicURL: publicURL}); err == nil {
		t.Fatal("missing audiences accepted")
	}
}
