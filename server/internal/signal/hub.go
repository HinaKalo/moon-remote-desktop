// Package signal runs the WebSocket signalling hub: presence of devices and relaying
// of session setup messages (invites, SDP, ICE candidates, QUIC endpoints) between
// connections of the same account.
//
// The hub never sees media or PINs. Session authentication (SPAKE2) is bound to the
// transport, so a compromised hub can deny service but cannot impersonate a peer.
//
// Connecting: POST /v1/signal/ticket (user or device credentials) returns a single-use
// ticket valid for 30 s; then open GET /v1/signal?ticket=… as a WebSocket. Tickets
// exist because browsers cannot set an Authorization header on WebSockets.
package signal

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/httpx"
	"moon-remote/server/internal/store"
)

// Limits.
const (
	MaxMessageBytes = 64 << 10
	sendQueue       = 64
	pingInterval    = 30 * time.Second
	pingTimeout     = 10 * time.Second
	ticketTTL       = 30 * time.Second
	maxTickets      = 10_000
	// Per-connection rate limit: sustained msgs/s and burst.
	rateLimit = 50
	rateBurst = 200
)

// RelayTypes are the client message types the hub forwards. Anything else is rejected.
var RelayTypes = map[string]bool{
	"invite": true, "accept": true, "reject": true,
	"sdp": true, "ice": true, "quic-endpoint": true, "bye": true,
}

// Inbound is a message from a client.
type Inbound struct {
	Type    string          `json:"type"`
	To      string          `json:"to,omitempty"`     // target device id
	ToConn  string          `json:"toConn,omitempty"` // target connection id (web viewers have no device)
	Session string          `json:"session,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Outbound is a message to a client.
type Outbound struct {
	Type     string          `json:"type"`
	From     string          `json:"from,omitempty"`     // sender device id, empty for web viewers
	FromConn string          `json:"fromConn,omitempty"` // sender connection id
	FromName string          `json:"fromName,omitempty"` // sender's account display name
	Session  string          `json:"session,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	// Server-originated fields.
	Conn   string   `json:"conn,omitempty"`
	Device string   `json:"device,omitempty"`
	Online *bool    `json:"online,omitempty"`
	List   []string `json:"list,omitempty"`
	Code   string   `json:"code,omitempty"`
}

type conn struct {
	id   string
	p    auth.Principal
	send chan []byte
	ws   *websocket.Conn
	// closed is closed once the connection is being torn down.
	closed    chan struct{}
	closeOnce sync.Once

	tokens   float64
	lastFill time.Time
}

func (c *conn) shutdown(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.ws.Close(code, reason)
	})
}

// Hub tracks live connections.
type Hub struct {
	Auth  *auth.Authenticator
	Store store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// OriginPatterns are extra allowed browser origins (host patterns) besides same-origin.
	OriginPatterns []string

	mu       sync.Mutex
	conns    map[string]*conn
	byDevice map[string]map[string]*conn
	byUser   map[string]map[string]*conn

	tmu     sync.Mutex
	tickets map[string]ticket
}

type ticket struct {
	p       auth.Principal
	expires time.Time
}

func (h *Hub) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Register adds the ticket and WebSocket routes.
func (h *Hub) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/signal/ticket", h.Auth.Require(auth.AllowAny, http.HandlerFunc(h.issueTicket)))
	mux.HandleFunc("GET /v1/signal", h.serveWS)
}

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Hub) issueTicket(w http.ResponseWriter, r *http.Request) {
	p, _ := auth.FromContext(r.Context())
	now := h.now()
	h.tmu.Lock()
	if h.tickets == nil {
		h.tickets = map[string]ticket{}
	}
	if len(h.tickets) >= maxTickets {
		for k, t := range h.tickets {
			if !now.Before(t.expires) {
				delete(h.tickets, k)
			}
		}
	}
	if len(h.tickets) >= maxTickets {
		h.tmu.Unlock()
		httpx.WriteError(w, http.StatusTooManyRequests, "busy", "try again shortly")
		return
	}
	id := randomID(24)
	h.tickets[id] = ticket{p: p, expires: now.Add(ticketTTL)}
	h.tmu.Unlock()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ticket": id, "expiresAt": now.Add(ticketTTL).UTC()})
}

func (h *Hub) redeem(id string) (auth.Principal, bool) {
	h.tmu.Lock()
	defer h.tmu.Unlock()
	t, ok := h.tickets[id]
	if !ok {
		return auth.Principal{}, false
	}
	delete(h.tickets, id)
	return t.p, h.now().Before(t.expires)
}

func (h *Hub) serveWS(w http.ResponseWriter, r *http.Request) {
	p, ok := h.redeem(r.URL.Query().Get("ticket"))
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "bad_ticket", "ticket unknown, expired or used")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.OriginPatterns})
	if err != nil {
		return // Accept already wrote the response
	}
	ws.SetReadLimit(MaxMessageBytes)
	c := &conn{id: randomID(12), p: p, send: make(chan []byte, sendQueue), ws: ws, closed: make(chan struct{}), tokens: rateBurst, lastFill: h.now()}
	h.add(c)
	defer h.remove(c)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go h.writeLoop(ctx, c)

	h.deliver(c, Outbound{Type: "welcome", Conn: c.id, Device: p.DeviceID})
	h.deliver(c, Outbound{Type: "presence-snapshot", List: h.onlineDevices(p.UserSub)})
	h.readLoop(ctx, c)
}

func (h *Hub) readLoop(ctx context.Context, c *conn) {
	for {
		typ, data, err := c.ws.Read(ctx)
		if err != nil {
			c.shutdown(websocket.StatusNormalClosure, "")
			return
		}
		if typ != websocket.MessageText {
			c.shutdown(websocket.StatusUnsupportedData, "text frames only")
			return
		}
		if !h.allow(c) {
			c.shutdown(websocket.StatusPolicyViolation, "rate limit")
			return
		}
		var in Inbound
		if err := json.Unmarshal(data, &in); err != nil {
			h.deliver(c, Outbound{Type: "error", Code: "bad_json"})
			continue
		}
		h.route(c, in)
	}
}

func (h *Hub) writeLoop(ctx context.Context, c *conn) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-ctx.Done():
			return
		case msg := <-c.send:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.ws.Write(wctx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				c.shutdown(websocket.StatusGoingAway, "write failed")
				return
			}
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, pingTimeout)
			err := c.ws.Ping(pctx)
			cancel()
			if err != nil {
				c.shutdown(websocket.StatusGoingAway, "ping timeout")
				return
			}
		}
	}
}

// allow applies the per-connection token bucket. Only the read loop calls it.
func (h *Hub) allow(c *conn) bool {
	now := h.now()
	c.tokens += now.Sub(c.lastFill).Seconds() * rateLimit
	if c.tokens > rateBurst {
		c.tokens = rateBurst
	}
	c.lastFill = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

func (h *Hub) route(from *conn, in Inbound) {
	if !RelayTypes[in.Type] {
		h.deliver(from, Outbound{Type: "error", Code: "unknown_type", Session: in.Session})
		return
	}
	if (in.To == "") == (in.ToConn == "") {
		h.deliver(from, Outbound{Type: "error", Code: "bad_target", Session: in.Session})
		return
	}
	targets := h.targets(from, in)
	if len(targets) == 0 {
		// Same answer for "offline" and "not yours", so ids of other accounts cannot be probed.
		h.deliver(from, Outbound{Type: "error", Code: "peer_offline", Session: in.Session})
		return
	}
	out := Outbound{Type: in.Type, From: from.p.DeviceID, FromConn: from.id, FromName: from.p.DisplayName, Session: in.Session, Data: in.Data}
	for _, t := range targets {
		h.deliver(t, out)
	}
}

// targets returns the receiving connections, applying the routing rule: only
// connections of the same account. (Phase 7 adds support-session grants here.)
func (h *Hub) targets(from *conn, in Inbound) []*conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*conn
	if in.ToConn != "" {
		if t, ok := h.conns[in.ToConn]; ok && t != from && t.p.UserSub == from.p.UserSub {
			out = append(out, t)
		}
		return out
	}
	for _, t := range h.byDevice[in.To] {
		if t != from && t.p.UserSub == from.p.UserSub {
			out = append(out, t)
		}
	}
	return out
}

// deliver queues a message; a client that cannot keep up is disconnected rather than
// letting its queue grow without bound.
func (h *Hub) deliver(c *conn, m Outbound) {
	b, err := json.Marshal(m)
	if err != nil {
		h.Log.Error("marshal signal message", "err", err)
		return
	}
	select {
	case c.send <- b:
	case <-c.closed:
	default:
		go c.shutdown(websocket.StatusTryAgainLater, "too slow")
	}
}

func (h *Hub) add(c *conn) {
	h.mu.Lock()
	if h.conns == nil {
		h.conns, h.byDevice, h.byUser = map[string]*conn{}, map[string]map[string]*conn{}, map[string]map[string]*conn{}
	}
	h.conns[c.id] = c
	addTo(h.byUser, c.p.UserSub, c)
	firstForDevice := false
	if c.p.IsDevice() {
		firstForDevice = len(h.byDevice[c.p.DeviceID]) == 0
		addTo(h.byDevice, c.p.DeviceID, c)
	}
	peers := h.userConnsLocked(c.p.UserSub, c)
	h.mu.Unlock()

	if c.p.IsDevice() {
		if err := h.Store.TouchDevice(context.Background(), c.p.DeviceID, h.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.Log.Warn("touch device", "device", c.p.DeviceID, "err", err)
		}
		if firstForDevice {
			online := true
			for _, p := range peers {
				h.deliver(p, Outbound{Type: "presence", Device: c.p.DeviceID, Online: &online})
			}
		}
	}
}

func (h *Hub) remove(c *conn) {
	c.shutdown(websocket.StatusNormalClosure, "")
	h.mu.Lock()
	delete(h.conns, c.id)
	removeFrom(h.byUser, c.p.UserSub, c)
	lastForDevice := false
	if c.p.IsDevice() {
		removeFrom(h.byDevice, c.p.DeviceID, c)
		lastForDevice = len(h.byDevice[c.p.DeviceID]) == 0
	}
	peers := h.userConnsLocked(c.p.UserSub, nil)
	h.mu.Unlock()

	if lastForDevice {
		online := false
		for _, p := range peers {
			h.deliver(p, Outbound{Type: "presence", Device: c.p.DeviceID, Online: &online})
		}
	}
}

func (h *Hub) userConnsLocked(sub string, except *conn) []*conn {
	var out []*conn
	for _, c := range h.byUser[sub] {
		if c != except {
			out = append(out, c)
		}
	}
	return out
}

func (h *Hub) onlineDevices(sub string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, c := range h.byUser[sub] {
		if c.p.IsDevice() && !seen[c.p.DeviceID] {
			seen[c.p.DeviceID] = true
			out = append(out, c.p.DeviceID)
		}
	}
	return out
}

// Online implements devices.Presence.
func (h *Hub) Online(deviceID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.byDevice[deviceID]) > 0
}

// Disconnect implements devices.Presence: closes all connections of a removed device.
func (h *Hub) Disconnect(deviceID string) {
	h.mu.Lock()
	var victims []*conn
	for _, c := range h.byDevice[deviceID] {
		victims = append(victims, c)
	}
	h.mu.Unlock()
	// Close in the background: the close handshake waits (up to 5 s) for the peer's
	// reply, and the caller is an HTTP request that should not wait on a slow client.
	for _, c := range victims {
		go c.shutdown(websocket.StatusPolicyViolation, "device removed")
	}
}

func addTo(m map[string]map[string]*conn, key string, c *conn) {
	if m[key] == nil {
		m[key] = map[string]*conn{}
	}
	m[key][c.id] = c
}

func removeFrom(m map[string]map[string]*conn, key string, c *conn) {
	delete(m[key], c.id)
	if len(m[key]) == 0 {
		delete(m, key)
	}
}
