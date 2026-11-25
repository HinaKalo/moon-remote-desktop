package devices

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/roster"
	"moon-remote/server/internal/store"
)

type fakePresence struct {
	mu           sync.Mutex
	online       map[string]bool
	disconnected []string
}

func (f *fakePresence) Online(id string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.online[id] }
func (f *fakePresence) Disconnect(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnected = append(f.disconnected, id)
}

type fakeRevoker struct {
	fail    bool
	revoked []string
}

func (f *fakeRevoker) RevokeDevice(_ context.Context, d store.Device) error {
	if f.fail {
		return errors.New("easytier down")
	}
	f.revoked = append(f.revoked, d.ID)
	return nil
}

type env struct {
	srv      *httptest.Server
	store    *store.Memory
	presence *fakePresence
	revoker  *fakeRevoker
	signer   *roster.Signer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	_, rk, _ := ed25519.GenerateKey(nil)
	e := &env{store: store.NewMemory(), presence: &fakePresence{online: map[string]bool{}}, revoker: &fakeRevoker{}, signer: roster.NewSigner(rk)}
	api := &API{
		Store:      e.store,
		Auth:       &auth.Authenticator{Users: auth.DevVerifier{}, Store: e.store},
		Challenges: &auth.Challenges{TTL: time.Minute, Max: 100},
		Roster:     e.signer,
		Presence:   e.presence,
		Revoker:    e.revoker,
		Log:        slog.New(slog.DiscardHandler),
	}
	mux := http.NewServeMux()
	api.Register(mux)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(t *testing.T, method, path, authz string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
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

type registered struct {
	id, token string
	priv      ed25519.PrivateKey
}

func (e *env) register(t *testing.T, user, kind string) registered {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	code, ch := e.do(t, "POST", "/v1/devices/challenge", "Dev "+user, nil)
	if code != 200 {
		t.Fatalf("challenge: %d %v", code, ch)
	}
	nonce := ch["nonce"].(string)
	sig := ed25519.Sign(priv, RegistrationMessage(nonce, "dev|"+user, store.DeviceKind(kind), pubB64))
	code, out := e.do(t, "POST", "/v1/devices", "Dev "+user, map[string]string{
		"name": "PC of " + user, "kind": kind, "publicKey": pubB64, "nonce": nonce,
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
	if code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, out)
	}
	if out["rosterKey"] != base64.StdEncoding.EncodeToString(e.signer.PublicKey()) {
		t.Fatalf("roster key not returned: %v", out)
	}
	return registered{id: out["device"].(map[string]any)["id"].(string), token: out["deviceToken"].(string), priv: priv}
}

func TestRegisterListRenameDelete(t *testing.T) {
	e := newEnv(t)
	host := e.register(t, "alice", "host")
	viewer := e.register(t, "alice", "viewer")
	e.presence.online[host.id] = true

	code, out := e.do(t, "GET", "/v1/devices", "Device "+viewer.token, nil)
	if code != 200 {
		t.Fatalf("list: %d", code)
	}
	list := out["devices"].([]any)
	if len(list) != 2 {
		t.Fatalf("want 2 devices: %v", list)
	}
	// Both devices can share a createdAt tick, so find them by id rather than position.
	byID := map[string]map[string]any{}
	for _, d := range list {
		m := d.(map[string]any)
		byID[m["id"].(string)] = m
	}
	h, v := byID[host.id], byID[viewer.id]
	if h == nil || v == nil || h["online"] != true || h["self"] == true || v["online"] != false || v["self"] != true {
		t.Fatalf("list content: %v", list)
	}

	if code, _ := e.do(t, "PATCH", "/v1/devices/"+host.id, "Dev alice", map[string]string{"name": "  书房电脑  "}); code != 204 {
		t.Fatalf("rename: %d", code)
	}
	d, _ := e.store.GetDevice(context.Background(), "dev|alice", host.id)
	if d.Name != "书房电脑" {
		t.Fatalf("rename not trimmed/stored: %q", d.Name)
	}
	if code, _ := e.do(t, "PATCH", "/v1/devices/"+host.id, "Dev alice", map[string]string{"name": "bad\x00name"}); code != 400 {
		t.Fatalf("control char accepted: %d", code)
	}

	if code, _ := e.do(t, "DELETE", "/v1/devices/"+host.id, "Dev alice", nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if len(e.revoker.revoked) != 1 || e.revoker.revoked[0] != host.id || len(e.presence.disconnected) != 1 {
		t.Fatalf("delete must revoke and disconnect: %v %v", e.revoker.revoked, e.presence.disconnected)
	}
	if code, _ := e.do(t, "GET", "/v1/devices", "Device "+host.token, nil); code != 401 {
		t.Fatalf("deleted device token still works: %d", code)
	}
}

func TestCrossAccountIsolation(t *testing.T) {
	e := newEnv(t)
	alice := e.register(t, "alice", "host")
	_ = e.register(t, "bob", "host")
	if code, _ := e.do(t, "PATCH", "/v1/devices/"+alice.id, "Dev bob", map[string]string{"name": "pwned"}); code != 404 {
		t.Fatalf("bob renamed alice's device: %d", code)
	}
	if code, _ := e.do(t, "DELETE", "/v1/devices/"+alice.id, "Dev bob", nil); code != 404 {
		t.Fatalf("bob deleted alice's device: %d", code)
	}
	_, out := e.do(t, "GET", "/v1/devices", "Dev bob", nil)
	for _, d := range out["devices"].([]any) {
		if d.(map[string]any)["id"] == alice.id {
			t.Fatal("bob sees alice's device")
		}
	}
}

func TestDeviceMayOnlyRemoveItself(t *testing.T) {
	e := newEnv(t)
	a := e.register(t, "alice", "host")
	b := e.register(t, "alice", "viewer")
	if code, _ := e.do(t, "DELETE", "/v1/devices/"+a.id, "Device "+b.token, nil); code != 403 {
		t.Fatalf("device removed a sibling: %d", code)
	}
	if code, _ := e.do(t, "DELETE", "/v1/devices/"+b.id, "Device "+b.token, nil); code != 204 {
		t.Fatalf("device could not remove itself: %d", code)
	}
}

func TestRevokeFailureKeepsDevice(t *testing.T) {
	e := newEnv(t)
	a := e.register(t, "alice", "host")
	e.revoker.fail = true
	if code, _ := e.do(t, "DELETE", "/v1/devices/"+a.id, "Dev alice", nil); code != http.StatusBadGateway {
		t.Fatalf("want 502 when revoke fails: %d", code)
	}
	if _, err := e.store.GetDevice(context.Background(), "dev|alice", a.id); err != nil {
		t.Fatal("device must stay registered when revoke fails")
	}
}

func TestRegistrationRejections(t *testing.T) {
	e := newEnv(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	challenge := func(user string) string {
		_, ch := e.do(t, "POST", "/v1/devices/challenge", "Dev "+user, nil)
		return ch["nonce"].(string)
	}
	post := func(user string, body map[string]string) int {
		code, _ := e.do(t, "POST", "/v1/devices", "Dev "+user, body)
		return code
	}
	sign := func(nonce, sub, kind string) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, RegistrationMessage(nonce, sub, store.DeviceKind(kind), pubB64)))
	}

	// Signature made for another account.
	n := challenge("alice")
	if c := post("alice", map[string]string{"name": "x", "kind": "host", "publicKey": pubB64, "nonce": n, "signature": sign(n, "dev|mallory", "host")}); c != 400 {
		t.Fatalf("foreign-account signature: %d", c)
	}
	// The nonce from that failed attempt is spent.
	if c := post("alice", map[string]string{"name": "x", "kind": "host", "publicKey": pubB64, "nonce": n, "signature": sign(n, "dev|alice", "host")}); c != 400 {
		t.Fatalf("spent nonce reused: %d", c)
	}
	// Signed as viewer, submitted as host.
	n = challenge("alice")
	if c := post("alice", map[string]string{"name": "x", "kind": "host", "publicKey": pubB64, "nonce": n, "signature": sign(n, "dev|alice", "viewer")}); c != 400 {
		t.Fatalf("kind swap: %d", c)
	}
	// Bob cannot use alice's nonce.
	n = challenge("alice")
	if c := post("bob", map[string]string{"name": "x", "kind": "host", "publicKey": pubB64, "nonce": n, "signature": sign(n, "dev|bob", "host")}); c != 400 {
		t.Fatalf("nonce of another user: %d", c)
	}
	// Valid, then the same key again.
	n = challenge("alice")
	if c := post("alice", map[string]string{"name": "x", "kind": "host", "publicKey": pubB64, "nonce": n, "signature": sign(n, "dev|alice", "host")}); c != 201 {
		t.Fatalf("valid registration: %d", c)
	}
	n = challenge("alice")
	if c := post("alice", map[string]string{"name": "x", "kind": "host", "publicKey": pubB64, "nonce": n, "signature": sign(n, "dev|alice", "host")}); c != 409 {
		t.Fatalf("duplicate key: %d", c)
	}
	// Device tokens cannot register more devices.
	if code, _ := e.do(t, "POST", "/v1/devices/challenge", "Device mrdd_x", nil); code != 401 {
		t.Fatalf("device-token challenge: %d", code)
	}
}

func TestRosterIsSignedAndScoped(t *testing.T) {
	e := newEnv(t)
	a := e.register(t, "alice", "host")
	_ = e.register(t, "alice", "viewer")
	_ = e.register(t, "bob", "host")
	if code, _ := e.do(t, "GET", "/v1/roster", "Dev alice", nil); code != 401 {
		t.Fatalf("roster is device-only: %d", code)
	}
	code, out := e.do(t, "GET", "/v1/roster", "Device "+a.token, nil)
	if code != 200 {
		t.Fatalf("roster: %d", code)
	}
	sr := roster.Signed{Roster: out["roster"].(string), Signature: out["signature"].(string), KeyID: out["keyId"].(string)}
	r, err := roster.Verify(e.signer.PublicKey(), sr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if r.UserSub != "dev|alice" || len(r.Devices) != 2 {
		t.Fatalf("roster scope: %+v", r)
	}
}

func TestCleanName(t *testing.T) {
	long := ""
	for range MaxNameRunes {
		long += "名"
	}
	for in, ok := range map[string]bool{"PC": true, " 笔记本 ": true, "": false, "   ": false, long: true, long + "x": false, "a\tb": false, "\xff": false} {
		if _, got := cleanName(in); got != ok {
			t.Errorf("cleanName(%q) = %v, want %v", in, got, ok)
		}
	}
}

// TestRegistrationVector pins the signed registration format; the Rust host service has
// the same vector (core/crates/moonrd-service/src/state.rs, known_vector_matches_go_server).
func TestRegistrationVector(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 7
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, RegistrationMessage("nonce-1", "sub-1", store.KindHost, pub)))
	if pub != "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=" ||
		sig != "f83P7B4J4MFyqlbkCwBPI5NlzTkv1LzDRgCP+nYS/iJAK93Fl0DTpiGf+1lkN+pSNcKWcEAbS1o4WasgjuzhCQ==" {
		t.Fatalf("registration vector changed: %s %s", pub, sig)
	}
}
