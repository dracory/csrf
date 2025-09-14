package csrf

import (
	"net"
	"net/http"
	"strings"
)

// Options allows optional request binding and time granularity controls for CSRF token generation/validation.
// All fields are optional. If Request is nil or a Bind* flag is false, that attribute is not used.
// Granularity controls the time window used in the token: "day" (default) or "hour".
type Options struct {
	Request       *http.Request
	BindIP        bool
	BindUserAgent bool
	BindPath      bool
	BindMethod    bool
	Granularity   string // "day" (default) or "hour"
}

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

// buildTimeFormat returns the carbon format string based on options.
// Defaults to day-level granularity ("Ymd"). If opts.Granularity == "hour", returns "YmdH".
func buildTimeFormat(opts *Options) string {
	if opts != nil {
		switch strings.ToLower(strings.TrimSpace(opts.Granularity)) {
		case "hour", "hourly":
			return "YmdH"
		}
	}
	return "Ymd"
}
