package auth

import (
	"net"
	"net/http"
	"strings"
)

// DevVerifier authenticates users for local development only:
//
//	Authorization: Dev <sub>[;<display name>]
//
// It accepts requests only from a loopback peer address, and config.Load only allows
// it when the server's public URL is itself a loopback address, so it cannot be
// switched on in a deployment reachable from outside.
type DevVerifier struct{}

func (DevVerifier) VerifyUser(r *http.Request) (VerifiedUser, error) {
	if !loopbackPeer(r.RemoteAddr) {
		return VerifiedUser{}, ErrUnauthenticated
	}
	scheme, cred, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Dev") {
		return VerifiedUser{}, ErrUnauthenticated
	}
	sub, name, _ := strings.Cut(strings.TrimSpace(cred), ";")
	sub, name = strings.TrimSpace(sub), strings.TrimSpace(name)
	if sub == "" || len(sub) > 255 {
		return VerifiedUser{}, ErrUnauthenticated
	}
	if name == "" {
		name = sub
	}
	return VerifiedUser{Sub: "dev|" + sub, DisplayName: name}, nil
}

func loopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
