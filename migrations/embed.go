// Package migrations embeds the schema so the binary carries its own
// migrations. A self-hosted deployment upgrades by replacing one file.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
