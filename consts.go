package csrf

import "time"

// CSRF_TOKEN_MIXIN is a static app-wide mix-in used to augment weak or empty secrets.
// It is not a secret unless sourced from configuration or environment.
const CSRF_TOKEN_MIXIN = "HGEGY#G$tewdRwvweRftrsTcHyr"

// DefaultPackagedExpiry is the default TTL for packaged tokens when Options.ExpiresAt is not set.
// Deterministic rule: issue time (UTC) + 15 minutes.
const DefaultPackagedExpiry = 15 * time.Minute
