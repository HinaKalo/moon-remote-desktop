// Package httpapi wires the HTTP routes of moon-remote-server.
package httpapi

import (
	"net/http"

	"moon-remote/server/internal/config"
	"moon-remote/server/internal/httpx"
)

// Info is the public, unauthenticated description of this deployment. Clients use it to
// find the SSO issuer and the installer download link.
type Info struct {
	Service         string `json:"service"`
	Version         string `json:"version"`
	SSOIssuer       string `json:"ssoIssuer"`
	WindowsDownload string `json:"windowsDownload"`
	ProtocolVersion int    `json:"protocolVersion"`
}

// ProtocolVersion matches Hello.protocol_version in proto/moonrd.proto.
const ProtocolVersion = 1

// Registrar adds a group of routes.
type Registrar interface {
	Register(mux *http.ServeMux)
}

// New returns the root handler with the public routes plus every registrar's routes.
func New(cfg config.Config, version string, apis ...Registrar) http.Handler {
	info := Info{
		Service:         "moon-remote-server",
		Version:         version,
		SSOIssuer:       cfg.SSOIssuer,
		WindowsDownload: cfg.WindowsDownloadURL(),
		ProtocolVersion: ProtocolVersion,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /v1/info", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, info)
	})
	for _, a := range apis {
		a.Register(mux)
	}
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
