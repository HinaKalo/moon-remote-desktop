package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"moon-remote/server/internal/config"
	"moon-remote/server/internal/devices"
	"moon-remote/server/internal/store"
)

// TestDevServerSmoke drives the assembled server the way a client would.
func TestDevServerSmoke(t *testing.T) {
	cfg, err := config.Load(func(k string) string {
		return map[string]string{"MRD_DEV": "1", "MRD_PUBLIC_URL": "http://127.0.0.1:8621"}[k]
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

	do := func(method, path, authz string, body any) (int, map[string]any) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(b))
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if authz != "" {
			req.Header.Set("Authorization", authz)
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

	_, ch := do("POST", "/v1/devices/challenge", "Dev alice", nil)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	nonce := ch["nonce"].(string)
	sig := ed25519.Sign(priv, devices.RegistrationMessage(nonce, "dev|alice", store.KindHost, pubB64))
	code, reg := do("POST", "/v1/devices", "Dev alice", map[string]string{
		"name": "Host", "kind": "host", "publicKey": pubB64, "nonce": nonce, "signature": base64.StdEncoding.EncodeToString(sig),
	})
	if code != 201 {
		t.Fatalf("register: %d %v", code, reg)
	}
	devAuth := "Device " + reg["deviceToken"].(string)

	checks := []struct {
		method, path, authz string
		body                any
		want                int
	}{
		{"GET", "/healthz", "", nil, 200},
		{"GET", "/v1/info", "", nil, 200},
		{"GET", "/v1/devices", devAuth, nil, 200},
		{"GET", "/v1/roster", devAuth, nil, 200},
		{"POST", "/v1/signal/ticket", devAuth, nil, 200},
		{"POST", "/v1/et/credential", devAuth, map[string]any{"occupied": []string{}}, 503}, // issuer pending Phase 0a
		{"GET", "/v1/turn", devAuth, nil, 503},                                              // TURN not configured
		{"GET", "/v1/devices", "", nil, 401},
	}
	for _, c := range checks {
		if code, out := do(c.method, c.path, c.authz, c.body); code != c.want {
			t.Errorf("%s %s = %d, want %d (%v)", c.method, c.path, code, c.want, out)
		}
	}
}
