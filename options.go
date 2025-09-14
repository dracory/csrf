package csrf

import (
	"net/http"
	"time"
)

// Options allows optional request binding for CSRF token generation/validation,
// and lets you set an absolute expiry for packaged tokens.
// All fields are optional. If Request is nil or a Bind* flag is false, that attribute is not used.
// ExpiresAt controls the expiry timestamp embedded into packaged tokens.
type Options struct {
	// Request is the incoming HTTP request whose attributes can be bound into the token.
	// If nil, no request attributes are used regardless of the Bind* flags.
	Request *http.Request

	// BindIP, when true, mixes the client IP (X-Forwarded-For first, then X-Real-IP,
	// then RemoteAddr) into the token. This reduces token reuse from different IPs.
	BindIP bool

	// BindUserAgent, when true, mixes the request's User-Agent header into the token.
	// This helps constrain reuse across different clients/browsers.
	BindUserAgent bool

	// BindPath, when true, mixes the request URL path into the token, constraining
	// a token to a specific endpoint/path.
	BindPath bool

	// BindMethod, when true, mixes the HTTP method (e.g., POST) into the token.
	// Useful if you want tokens to be valid only for a given method.
	BindMethod bool

	// ExpiresAt sets the absolute expiry (UTC) for packaged tokens. If zero, the generator
	// uses a deterministic default of now (UTC) + DefaultPackagedExpiry.
	ExpiresAt time.Time
}
