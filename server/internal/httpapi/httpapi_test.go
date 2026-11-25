package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"moon-remote/server/internal/config"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{"MRD_DEV": "1", "MRD_PUBLIC_URL": "http://127.0.0.1:8621"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(cfg, "0.1.0-test"))
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthz(t *testing.T) {
	srv := newServer(t)
	res, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers missing")
	}
}

func TestInfo(t *testing.T) {
	srv := newServer(t)
	res, err := http.Get(srv.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var info Info
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info.Version != "0.1.0-test" || info.ProtocolVersion != 1 || info.SSOIssuer != "https://sso.moonl.cloud" {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	srv := newServer(t)
	res, err := http.Post(srv.URL+"/v1/info", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/info status %d, want 405", res.StatusCode)
	}
}
