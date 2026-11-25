package signal

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/store"
)

type env struct {
	srv   *httptest.Server
	hub   *Hub
	store *store.Memory
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := store.NewMemory()
	a := &auth.Authenticator{Users: auth.DevVerifier{}, Store: st}
	h := &Hub{Auth: a, Store: st, Log: slog.New(slog.DiscardHandler)}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{srv: srv, hub: h, store: st}
}

// device registers a device for user and returns its "Device <token>" header and id.
func (e *env) device(t *testing.T, user string) (string, string) {
	t.Helper()
	now := time.Now()
	sub := "dev|" + user
	_ = e.store.UpsertUser(context.Background(), store.User{Sub: sub, DisplayName: user, CreatedAt: now, UpdatedAt: now})
	tok, hash := auth.NewDeviceToken()
	pub := make([]byte, 32)
	_, _ = rand.Read(pub)
	id := auth.NewID()
	if err := e.store.CreateDevice(context.Background(), store.Device{ID: id, UserSub: sub, Name: "PC", Kind: store.KindHost, PublicKey: pub, TokenHash: hash, CreatedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	return "Device " + tok, id
}

func (e *env) ticket(t *testing.T, authz string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/signal/ticket", nil)
	req.Header.Set("Authorization", authz)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("ticket: %d", res.StatusCode)
	}
	var out struct{ Ticket string }
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out.Ticket
}

type client struct {
	t  *testing.T
	ws *websocket.Conn
	id string
}

func (e *env) connect(t *testing.T, authz string) *client {
	t.Helper()
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/v1/signal?ticket=" + e.ticket(t, authz)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	c := &client{t: t, ws: ws}
	w := c.next()
	if w.Type != "welcome" || w.Conn == "" {
		t.Fatalf("first message: %+v", w)
	}
	c.id = w.Conn
	if s := c.next(); s.Type != "presence-snapshot" {
		t.Fatalf("second message: %+v", s)
	}
	return c
}

func (c *client) next() Outbound {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, b, err := c.ws.Read(ctx)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	var m Outbound
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

func (c *client) send(m Inbound) {
	c.t.Helper()
	b, _ := json.Marshal(m)
	if err := c.ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		c.t.Fatal(err)
	}
}

func TestPresenceAndRelay(t *testing.T) {
	e := newEnv(t)
	viewer := e.connect(t, "Dev alice;Alice") // web viewer: user credentials, no device
	hostAuth, hostID := e.device(t, "alice")
	host := e.connect(t, hostAuth)

	p := viewer.next()
	if p.Type != "presence" || p.Device != hostID || p.Online == nil || !*p.Online {
		t.Fatalf("presence online: %+v", p)
	}
	if !e.hub.Online(hostID) {
		t.Fatal("hub.Online")
	}

	viewer.send(Inbound{Type: "invite", To: hostID, Session: "s1", Data: json.RawMessage(`{"kind":"remote_access"}`)})
	got := host.next()
	if got.Type != "invite" || got.FromConn != viewer.id || got.From != "" || got.FromName != "Alice" || got.Session != "s1" || string(got.Data) != `{"kind":"remote_access"}` {
		t.Fatalf("relayed invite: %+v", got)
	}
	host.send(Inbound{Type: "accept", ToConn: viewer.id, Session: "s1"})
	if r := viewer.next(); r.Type != "accept" || r.From != hostID {
		t.Fatalf("reply: %+v", r)
	}

	host.ws.Close(websocket.StatusNormalClosure, "")
	if p := viewer.next(); p.Type != "presence" || p.Online == nil || *p.Online {
		t.Fatalf("presence offline: %+v", p)
	}
}

func TestCrossAccountBlocked(t *testing.T) {
	e := newEnv(t)
	hostAuth, hostID := e.device(t, "alice")
	host := e.connect(t, hostAuth)
	mallory := e.connect(t, "Dev mallory")

	mallory.send(Inbound{Type: "invite", To: hostID, Session: "x"})
	if r := mallory.next(); r.Type != "error" || r.Code != "peer_offline" {
		t.Fatalf("cross-account invite: %+v", r)
	}
	mallory.send(Inbound{Type: "sdp", ToConn: host.id, Session: "x"})
	if r := mallory.next(); r.Code != "peer_offline" {
		t.Fatalf("cross-account by conn: %+v", r)
	}
	// Mallory must not have seen alice's host in the snapshot either; send a probe to
	// alice's host and check it received nothing by pinging it with its own account.
	viewer := e.connect(t, "Dev alice")
	viewer.send(Inbound{Type: "invite", To: hostID, Session: "ok"})
	if got := host.next(); got.Session != "ok" {
		t.Fatalf("host received a foreign message first: %+v", got)
	}
}

func TestRejectsBadInput(t *testing.T) {
	e := newEnv(t)
	c := e.connect(t, "Dev alice")
	c.send(Inbound{Type: "presence", To: "x"})
	if r := c.next(); r.Code != "unknown_type" {
		t.Fatalf("server-only type relayed: %+v", r)
	}
	c.send(Inbound{Type: "sdp", To: "a", ToConn: "b"})
	if r := c.next(); r.Code != "bad_target" {
		t.Fatalf("two targets: %+v", r)
	}
	_ = c.ws.Write(context.Background(), websocket.MessageText, []byte("{not json"))
	if r := c.next(); r.Code != "bad_json" {
		t.Fatalf("bad json: %+v", r)
	}
}

func TestTicketIsSingleUse(t *testing.T) {
	e := newEnv(t)
	tk := e.ticket(t, "Dev alice")
	url := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/v1/signal?ticket=" + tk
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	if _, res, err := websocket.Dial(ctx, url, nil); err == nil || res == nil || res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ticket reused: %v", err)
	}
	if _, res, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(e.srv.URL, "http")+"/v1/signal", nil); err == nil || res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no ticket: %v", err)
	}
}

func TestDisconnectRemovedDevice(t *testing.T) {
	e := newEnv(t)
	hostAuth, hostID := e.device(t, "alice")
	host := e.connect(t, hostAuth)
	e.hub.Disconnect(hostID)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := host.ws.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("want policy-violation close, got %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.hub.Online(hostID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.hub.Online(hostID) {
		t.Fatal("device still online after disconnect")
	}
}

func TestRateLimit(t *testing.T) {
	now := time.Unix(0, 0)
	h := &Hub{Now: func() time.Time { return now }}
	c := &conn{tokens: rateBurst, lastFill: now}
	for i := 0; i < rateBurst; i++ {
		if !h.allow(c) {
			t.Fatalf("burst refused at %d", i)
		}
	}
	if h.allow(c) {
		t.Fatal("over burst allowed")
	}
	now = now.Add(time.Second)
	for i := 0; i < rateLimit; i++ {
		if !h.allow(c) {
			t.Fatalf("refill refused at %d", i)
		}
	}
	if h.allow(c) {
		t.Fatal("over refill allowed")
	}
}
