// Package turn issues short-lived coturn credentials (coturn "use-auth-secret", the
// TURN REST API scheme): username "<expiry unix>:<id>", password
// base64(HMAC-SHA1(shared secret, username)). coturn checks the expiry itself, so a
// leaked credential stops working after TTL.
package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"

	"moon-remote/server/internal/auth"
	"moon-remote/server/internal/httpx"
)

// DefaultTTL bounds a single session's relay use; clients fetch new ones per session.
const DefaultTTL = 6 * time.Hour

// Issuer produces TURN credentials. A nil *Issuer or one without Secret means TURN is
// not configured and the endpoint answers 503.
type Issuer struct {
	Secret []byte
	// URLs as given to RTCPeerConnection, e.g. "turns:turn.remote.moonl.cloud:443?transport=tcp".
	URLs []string
	// STUN URLs handed out alongside.
	STUN []string
	TTL  time.Duration
	Auth *auth.Authenticator
	Now  func() time.Time
}

// Credentials is the JSON body, shaped like an RTCIceServer list.
type Credentials struct {
	ICEServers []ICEServer `json:"iceServers"`
	ExpiresAt  time.Time   `json:"expiresAt"`
}

// ICEServer matches the WebRTC RTCIceServer dictionary.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// For returns credentials for an opaque identity (never the raw user subject, since
// coturn logs usernames).
func (i *Issuer) For(identity string) Credentials {
	now := time.Now()
	if i.Now != nil {
		now = i.Now()
	}
	ttl := i.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	exp := now.Add(ttl)
	user := strconv.FormatInt(exp.Unix(), 10) + ":" + identity
	mac := hmac.New(sha1.New, i.Secret)
	mac.Write([]byte(user))
	var servers []ICEServer
	if len(i.STUN) > 0 {
		servers = append(servers, ICEServer{URLs: i.STUN})
	}
	servers = append(servers, ICEServer{URLs: i.URLs, Username: user, Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil))})
	return Credentials{ICEServers: servers, ExpiresAt: exp.UTC()}
}

// Identity derives the opaque TURN identity of a caller.
func Identity(p auth.Principal) string {
	if p.IsDevice() {
		return "d" + p.DeviceID[:12]
	}
	sum := sha256.Sum256([]byte(p.UserSub))
	return "u" + hex.EncodeToString(sum[:6])
}

// Register adds GET /v1/turn for users and devices.
func (i *Issuer) Register(mux *http.ServeMux, a *auth.Authenticator) {
	mux.Handle("GET /v1/turn", a.Require(auth.AllowAny, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i == nil || len(i.Secret) == 0 || len(i.URLs) == 0 {
			httpx.WriteError(w, http.StatusServiceUnavailable, "turn_unavailable", "relay is not configured")
			return
		}
		p, _ := auth.FromContext(r.Context())
		httpx.WriteJSON(w, http.StatusOK, i.For(Identity(p)))
	})))
}
