package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"moon-remote/server/internal/store"
)

func newAuth(t *testing.T) (*Authenticator, *store.Memory) {
	t.Helper()
	s := store.NewMemory()
	return &Authenticator{Users: DevVerifier{}, Store: s}, s
}

func call(a *Authenticator, allow Allow, authz, remote string) (*httptest.ResponseRecorder, Principal) {
	var got Principal
	h := a.Require(allow, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = FromContext(r.Context())
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w, got
}

func TestDevUserFromLoopbackOnly(t *testing.T) {
	a, s := newAuth(t)
	w, p := call(a, AllowUser, "Dev alice;Alice", "127.0.0.1:5000")
	if w.Code != 200 || p.UserSub != "dev|alice" || p.DisplayName != "Alice" || p.IsDevice() {
		t.Fatalf("loopback dev user: %d %+v", w.Code, p)
	}
	if _, err := s.GetUser(context.Background(), "dev|alice"); err != nil {
		t.Fatalf("user not upserted: %v", err)
	}
	if w, _ := call(a, AllowUser, "Dev alice", "203.0.113.9:5000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("remote dev user accepted: %d", w.Code)
	}
}

func TestMissingAndWrongKind(t *testing.T) {
	a, _ := newAuth(t)
	if w, _ := call(a, AllowAny, "", "127.0.0.1:1"); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no credentials: %d", w.Code)
	}
	if w, _ := call(a, AllowDevice, "Dev alice", "127.0.0.1:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("user on device-only route: %d", w.Code)
	}
	tok, _ := NewDeviceToken()
	if w, _ := call(a, AllowUser, "Device "+tok, "127.0.0.1:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("device on user-only route: %d", w.Code)
	}
}

func TestDeviceToken(t *testing.T) {
	a, s := newAuth(t)
	ctx := context.Background()
	now := time.Now()
	_ = s.UpsertUser(ctx, store.User{Sub: "u1", DisplayName: "U One", CreatedAt: now, UpdatedAt: now})
	tok, hash := NewDeviceToken()
	if err := s.CreateDevice(ctx, store.Device{ID: NewID(), UserSub: "u1", Name: "PC", Kind: store.KindHost,
		PublicKey: make([]byte, 32), TokenHash: hash, CreatedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	w, p := call(a, AllowDevice, "Device "+tok, "198.51.100.1:1")
	if w.Code != 200 || p.UserSub != "u1" || !p.IsDevice() || p.DisplayName != "U One" {
		t.Fatalf("device auth: %d %+v", w.Code, p)
	}
	other, _ := NewDeviceToken()
	if w, _ := call(a, AllowDevice, "Device "+other, "198.51.100.1:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", w.Code)
	}
	if w, _ := call(a, AllowDevice, "Device "+strings.TrimPrefix(tok, "mrdd_"), "198.51.100.1:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("malformed token: %d", w.Code)
	}
}

func TestUnconfiguredIs503(t *testing.T) {
	a := &Authenticator{Users: Unconfigured{}, Store: store.NewMemory()}
	if w, _ := call(a, AllowUser, "DPoP abc", "127.0.0.1:1"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured verifier: %d", w.Code)
	}
}

func TestHashDeviceToken(t *testing.T) {
	tok, hash := NewDeviceToken()
	got, ok := HashDeviceToken(tok)
	if !ok || string(got) != string(hash) {
		t.Fatal("hash mismatch")
	}
	for _, bad := range []string{"", "mrdd_", "mrdd_short", "xxxx_" + tok[5:], tok + "x", "mrdd_" + strings.Repeat("!", 43)} {
		if _, ok := HashDeviceToken(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	if a, b := NewID(), NewID(); len(a) != 32 || a == b {
		t.Fatal("NewID")
	}
}

func TestChallenges(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := &Challenges{TTL: time.Minute, Max: 2, Now: func() time.Time { return now }}
	n1, _, err := c.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if c.Consume("bob", n1) {
		t.Fatal("nonce accepted for another subject")
	}
	if c.Consume("alice", n1) {
		t.Fatal("nonce must be gone after a failed use")
	}
	n2, _, _ := c.Issue("alice")
	if !c.Consume("alice", n2) || c.Consume("alice", n2) {
		t.Fatal("nonce must work exactly once")
	}
	n3, _, _ := c.Issue("alice")
	now = now.Add(2 * time.Minute)
	if c.Consume("alice", n3) {
		t.Fatal("expired nonce accepted")
	}
	_, _, _ = c.Issue("a")
	_, _, _ = c.Issue("b")
	if _, _, err := c.Issue("c"); !errors.Is(err, ErrTooManyChallenges) {
		t.Fatalf("cap not enforced: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, _, err := c.Issue("c"); err != nil {
		t.Fatalf("expired entries must be swept: %v", err)
	}
}
