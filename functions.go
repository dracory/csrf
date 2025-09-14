package csrf

import (
	"net"
	"net/http"
	"strings"
)

// clientIP extracts a client IP address from the request using common proxy headers before
// falling back to RemoteAddr. Returns an empty string if r is nil.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	// Prefer X-Forwarded-For (first entry)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Fallback to X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Finally, RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// buildAugmentedSecret mixes optional request-bound attributes into the provided secret
// along with the static application mixin.
func buildAugmentedSecret(secret string, opts *Options) string {
	s := secret + CSRF_TOKEN_MIXIN
	if opts != nil && opts.Request != nil {
		r := opts.Request
		if opts.BindIP {
			s += "|ip:" + clientIP(r)
		}
		if opts.BindUserAgent {
			s += "|ua:" + r.UserAgent()
		}
		if opts.BindPath && r.URL != nil {
			s += "|path:" + r.URL.Path
		}
		if opts.BindMethod {
			s += "|method:" + r.Method
		}
	}
	return s
}
