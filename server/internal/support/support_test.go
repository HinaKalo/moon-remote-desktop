package support

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/store"
)

func TestSupportCodeLifecycleAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	st := store.NewMemory()
	authn := &auth.Authenticator{Users: auth.DevVerifier{}, Store: st}
	api := &API{Auth: authn, TTL: 5 * time.Minute, Now: func() time.Time { return now }}
	mux := http.NewServeMux()
	api.Register(mux)

	// 1. Alice creates a support code.
	req := httptest.NewRequest("POST", "/v1/support/codes", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Dev alice;Alice")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Code    string `json:"code"`
		Session string `json:"session"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Code) != 12 || created.Session == "" {
		t.Fatalf("unexpected code/session: %+v", created)
	}

	// 2. Bob (different SSO account) redeems it once.
	body, _ := json.Marshal(map[string]string{"code": created.Code[:4] + " " + created.Code[4:8] + " " + created.Code[8:]})
	req2 := httptest.NewRequest("POST", "/v1/support/redeem", bytes.NewReader(body))
	req2.RemoteAddr = "127.0.0.1:1234"
	req2.Header.Set("Authorization", "Dev bob;Bob")
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("redeem: %d %s", rec2.Code, rec2.Body.String())
	}
	var redeemed struct {
		Session  string `json:"session"`
		HostName string `json:"hostName"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &redeemed)
	if redeemed.Session != created.Session || redeemed.HostName != "Alice" {
		t.Fatalf("unexpected redeem: %+v", redeemed)
	}

	// 3. Reusing the same code fails with 404.
	req3 := httptest.NewRequest("POST", "/v1/support/redeem", bytes.NewReader(body))
	req3.RemoteAddr = "127.0.0.1:1234"
	req3.Header.Set("Authorization", "Dev bob;Bob")
	req3.Header.Set("Content-Type", "application/json")
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on reuse, got %d", rec3.Code)
	}

	// 4. Expired code fails with 404.
	rec4 := httptest.NewRecorder()
	mux.ServeHTTP(rec4, req)
	var expCreated struct{ Code string }
	_ = json.Unmarshal(rec4.Body.Bytes(), &expCreated)
	now = now.Add(6 * time.Minute)
	expBody, _ := json.Marshal(map[string]string{"code": expCreated.Code})
	req5 := httptest.NewRequest("POST", "/v1/support/redeem", bytes.NewReader(expBody))
	req5.RemoteAddr = "127.0.0.1:1234"
	req5.Header.Set("Authorization", "Dev bob;Bob")
	req5.Header.Set("Content-Type", "application/json")
	rec5 := httptest.NewRecorder()
	mux.ServeHTTP(rec5, req5)
	if rec5.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on expired code, got %d", rec5.Code)
	}
}
