// Package web serves the compiled TypeScript web controller SPA from disk (web/dist)
// when present, falling back to index.html for client-side routes.
package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Handler serves static SPA assets from Dir. If Dir does not exist, non-API requests
// return 404 cleanly so API-only deployments keep working.
type Handler struct {
	Dir string
}

func (h Handler) Register(mux *http.ServeMux) {
	if h.Dir == "" {
		return
	}
	info, err := os.Stat(h.Dir)
	if err != nil || !info.IsDir() {
		return
	}
	fs := http.FileServer(http.Dir(h.Dir))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" {
			http.NotFound(w, r)
			return
		}
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		target := filepath.Join(h.Dir, clean)
		if st, err := os.Stat(target); err == nil && !st.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(h.Dir, "index.html"))
	})
}
