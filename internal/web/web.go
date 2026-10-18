// Package web holds the embedded single-page interface. Assets are compiled
// into the binary so there is no runtime package manager, CDN, downloaded font,
// or remote script.
package web

import "embed"

// Assets contains the static UI files, served only from memory.
//
//go:embed assets/index.html assets/app.js assets/style.css
var Assets embed.FS
