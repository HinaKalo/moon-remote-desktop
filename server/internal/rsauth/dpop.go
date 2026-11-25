package rsauth

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// proofAlgs are the asymmetric algorithms accepted for DPoP proofs; the same
// list Moon SSO advertises in dpop_signing_alg_values_supported. "none" and
// HMAC algorithms are never accepted.
var proofAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256, jose.PS256, jose.EdDSA}

func proofAlgNames() []string {
	out := make([]string, len(proofAlgs))
	for i, a := range proofAlgs {
		out[i] = string(a)
	}
	return out
}

const maxProofLen = 8192

type proofClaims struct {
	Jti string `json:"jti"`
	Htm string `json:"htm"`
	Htu string `json:"htu"`
	Iat *int64 `json:"iat"`
	Ath string `json:"ath"`
}

// verifyProof validates a DPoP proof JWT for a resource request (RFC 9449 §4.3
// and §7.1) and returns the RFC 7638 thumbprint of its key.
func (v *Verifier) verifyProof(ctx context.Context, proof, method, htu, accessToken string) (string, *Error) {
	if len(proof) > maxProofLen {
		return "", proofErr("DPoP proof too large")
	}
	jws, err := jose.ParseSignedCompact(proof, proofAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return "", proofErr("malformed DPoP proof")
	}
	h := jws.Signatures[0].Header
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); typ != "dpop+jwt" {
		return "", proofErr("DPoP typ must be dpop+jwt")
	}
	jwk := h.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return "", proofErr("DPoP proof must embed a public JWK")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return "", proofErr("invalid DPoP signature")
	}
	var cl proofClaims
	if err := json.Unmarshal(payload, &cl); err != nil {
		return "", proofErr("malformed DPoP claims")
	}
	now := v.cfg.Now()
	switch {
	case cl.Jti == "" || len(cl.Jti) > 256:
		return "", proofErr("DPoP jti missing")
	case cl.Htm != method:
		return "", proofErr("DPoP htm mismatch")
	case !sameHTU(cl.Htu, htu):
		return "", proofErr("DPoP htu mismatch")
	case cl.Iat == nil:
		return "", proofErr("DPoP iat missing")
	}
	iat := time.Unix(*cl.Iat, 0)
	if iat.Before(now.Add(-v.cfg.ProofMaxAge)) || iat.After(now.Add(v.cfg.ProofSkew)) {
		return "", proofErr("DPoP iat outside the accepted window")
	}
	sum := sha256.Sum256([]byte(accessToken))
	if subtle.ConstantTimeCompare([]byte(cl.Ath), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) != 1 {
		return "", proofErr("DPoP ath does not match the access token")
	}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", proofErr("invalid DPoP key")
	}
	jkt := base64.RawURLEncoding.EncodeToString(tp)
	// Remember the jti until the proof could no longer pass the iat check.
	if !v.cfg.Replay.Add(ctx, jkt+"|"+cl.Jti, iat.Add(v.cfg.ProofMaxAge+v.cfg.ProofSkew)) {
		return "", proofErr("DPoP proof replayed")
	}
	return jkt, nil
}

// sameHTU compares two URIs after RFC 3986 syntax-based normalization of
// scheme, host and default port, ignoring query and fragment (RFC 9449 §4.3).
func sameHTU(got, want string) bool {
	g, err1 := normalizeHTU(got)
	w, err2 := normalizeHTU(want)
	return err1 == nil && err2 == nil && g == w
}

func normalizeHTU(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || u.Host == "" {
		return "", url.InvalidHostError(s)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// ReplayCache remembers DPoP proof identifiers.
type ReplayCache interface {
	// Add records key until expires and reports whether it was new.
	Add(ctx context.Context, key string, expires time.Time) bool
}

// MemoryReplayCache is a bounded in-process ReplayCache for a single
// instance. When full it evicts expired entries first and otherwise fails
// closed (rejects new proofs) rather than forgetting live ones.
type MemoryReplayCache struct {
	mu    sync.Mutex
	max   int
	items map[string]time.Time
	now   func() time.Time
}

// NewMemoryReplayCache returns a cache holding at most max live entries.
func NewMemoryReplayCache(max int) *MemoryReplayCache {
	return &MemoryReplayCache{max: max, items: map[string]time.Time{}, now: time.Now}
}

func (m *MemoryReplayCache) Add(_ context.Context, key string, expires time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if exp, ok := m.items[key]; ok && now.Before(exp) {
		return false
	}
	if len(m.items) >= m.max {
		for k, exp := range m.items {
			if !now.Before(exp) {
				delete(m.items, k)
			}
		}
		if len(m.items) >= m.max {
			return false
		}
	}
	m.items[key] = expires
	return true
}
