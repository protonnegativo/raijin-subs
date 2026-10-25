// Package raijinsubs holds the files the binary embeds from the repository root.
package raijinsubs

import _ "embed"

// EnginesJSON is engines.json: the engine versions the fixtures in bench/fixtures were produced with,
// and where to install each one from.
//
//go:embed engines.json
var EnginesJSON []byte
