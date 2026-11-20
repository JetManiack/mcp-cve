// Package frontend embeds and serves the admin UI.
package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
)

//go:generate npm --prefix ../../web install
//go:generate npm --prefix ../../web run build

//go:embed all:static
var assets embed.FS

// Handler returns an http.Handler that serves the embedded admin UI.
// Unknown paths fall back to index.html.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fsPath := strings.TrimPrefix(r.URL.Path, "/")
		if fsPath == "" {
			fsPath = "."
		}
		f, openErr := sub.Open(fsPath)
		if openErr == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL = &url.URL{Path: "/"}
		fileServer.ServeHTTP(w, r2)
	}), nil
}
