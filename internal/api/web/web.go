// Package web embeds the minimal animated single-page view served at "/"
// by the detector. The page polls /v1/anomalies and animates new cards
// in. No build step — plain HTML + a small JS module.
package web

import (
	"embed"
	"io/fs"
)

//go:embed assets
var assets embed.FS

// FS returns the embedded assets rooted at "assets/" so http.FileServer
// serves /index.html as the root.
func FS() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // unreachable: directory is statically embedded.
	}
	return sub
}
