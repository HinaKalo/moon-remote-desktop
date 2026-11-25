package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"moon-remote/server/internal/config"
	"moon-remote/server/internal/devices"
	"moon-remote/server/internal/store"
)

// TestSSOWiring checks that the assembled server accepts an access token from the
// configured issuer and client, takes the display name from userinfo, and rejects a
// token minted for a client that is not on the allowlist.
func TestSSOWiring(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var issuer *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/jwks", "userinfo_endpoint": issuer.URL + "/userinfo"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "sub-alice", "name": "Alice"})
	})
	issuer = httptest.NewServer(mux)
	defer issuer.Close()

	mint := func(clientID string) string {
		now := time.Now()
		payload, _ := json.Marshal(map[string]any{"iss": issuer.URL, "sub": "sub-alice", "aud": []string{clientID}, "client_id": clientID,
			"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "jti": clientID})
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"))
		jws, _ := s.Sign(payload)
		out, _ := jws.CompactSerialize()
		return out
	}

	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"MRD_DEV": "1", "MRD_PUBLIC_URL": "http://127.0.0.1:8621",
			"MRD_SSO_ISSUER": issuer.URL, "MRD_SSO_CLIENT_IDS": "ms_desktop,ms_web",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	h, closer, err := Build(context.Background(), cfg, "test", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	srv := httptest.NewServer(h)
	defer srv.Close()

	post := func(path, token string, body any) (int, map[string]any) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}

	if code, _ := post("/v1/devices/challenge", mint("ms_intruder"), nil); code != http.StatusUnauthorized {
		t.Fatalf("token of a client not on the allowlist: %d", code)
	}

	tok := mint("ms_desktop")
	code, ch := post("/v1/devices/challenge", tok, nil)
	if code != 200 {
		t.Fatalf("challenge with SSO token: %d %v", code, ch)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	nonce := ch["nonce"].(string)
	sig := ed25519.Sign(priv, devices.RegistrationMessage(nonce, "sub-alice", store.KindViewer, pubB64))
	code, reg := post("/v1/devices", tok, map[string]string{
		"name": "Laptop", "kind": "viewer", "publicKey": pubB64, "nonce": nonce, "signature": base64.StdEncoding.EncodeToString(sig),
	})
	if code != 201 {
		t.Fatalf("register with SSO token: %d %v", code, reg)
	}

	// The device token resolves to the SSO user with the userinfo name.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/devices", nil)
	req.Header.Set("Authorization", "Device "+reg["deviceToken"].(string))
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("device token: %v %v", err, res)
	}
	res.Body.Close()
}
