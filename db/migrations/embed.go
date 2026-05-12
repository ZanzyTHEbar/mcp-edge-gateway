package migrations

import "embed"

// Files embeds the SQL migrations shipped with the control plane.
//
//go:embed *.sql
var Files embed.FS
