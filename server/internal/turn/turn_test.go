package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"moon-remote/server/internal/auth"
)

func TestFor(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	i := &Issuer{Secret: []byte("s3cret"), URLs: []string{"turns:turn.example:443?transport=tcp"}, STUN: []string{"stun:turn.example:3478"}, TTL: time.Hour, Now: func() time.Time { return now }}
	c := i.For("d0123456789ab")
	if len(c.ICEServers) != 2 || c.ICEServers[0].Username != "" {
		t.Fatalf("servers: %+v", c.ICEServers)
	}
	relay := c.ICEServers[1]
	if relay.Username != "1800003600:d0123456789ab" || !c.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("username/expiry: %+v %v", relay, c.ExpiresAt)
	}
	mac := hmac.New(sha1.New, []byte("s3cret"))
	mac.Write([]byte(relay.Username))
	if relay.Credential != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("credential is not coturn's HMAC-SHA1")
	}
}

func TestIdentityIsOpaque(t *testing.T) {
	u := Identity(auth.Principal{UserSub: "user@example.com"})
	if strings.Contains(u, "example") || len(u) != 13 {
		t.Fatalf("user identity leaks or wrong size: %q", u)
	}
	if d := Identity(auth.Principal{UserSub: "x", DeviceID: "0123456789abcdef0123456789abcdef"}); d != "d0123456789ab" {
		t.Fatalf("device identity: %q", d)
	}
}
