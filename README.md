# CSRF <a href="https://gitpod.io/#https://github.com/dracory/csrf" style="float:right:"><img src="https://gitpod.io/button/open-in-gitpod.svg" alt="Open in Gitpod" loading="lazy"></a>

[![Tests Status](https://github.com/dracory/csrf/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/dracory/csrf/actions/workflows/tests.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dracory/csrf)](https://goreportcard.com/report/github.com/gouniverse/ui)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/dracory/csrf)](https://pkg.go.dev/github.com/dracory/csrf)

## Installation
```
go get -u github.com/dracory/csrf
```

## Overview
This package provides simple CSRF token generation and validation with optional request-bound attributes and packaged expiry.

- Tokens are generated via `TokenGenerate(secret, opts...)` and validated via `TokenValidate(token, secret, opts...)`.
- Callers treat the token as an opaque string. Packaging/unpackaging is handled internally.
- You can bind request attributes (IP, User-Agent, Path, Method) into the token to reduce reuse.
- Packaged tokens include an absolute expiry timestamp.

## Quick Start
```go
import (
    "net/http/httptest"
    "time"
    "github.com/dracory/csrf"
)

func example() bool {
    secret := "my-app-secret"
    r := httptest.NewRequest("POST", "/form/submit", nil)

    // Configure optional bindings and expiry
    opts := &csrf.Options{
        Request:      r,
        BindIP:       true,
        BindUserAgent:true,
        BindPath:     true,
        BindMethod:   true,
        ExpiresAt:    time.Now().UTC().Add(15 * time.Minute),
    }

    token := csrf.TokenGenerate(secret, opts)
    return csrf.TokenValidate(token, secret, opts)
}
```

## Options
`Options` lets you opt-in to binding request attributes into the token and set a fixed expiry time:

- `Request *http.Request`
  - The request whose attributes may be bound. If nil, binding flags are ignored.
- `BindIP bool`
  - Mixes the client IP (X-Forwarded-For first, then X-Real-IP, then RemoteAddr) into the token.
- `BindUserAgent bool`
  - Mixes the `User-Agent` header into the token.
- `BindPath bool`
  - Mixes the request URL path into the token. Tokens become path-specific.
- `BindMethod bool`
  - Mixes the HTTP method (e.g., POST) into the token. Tokens become method-specific.
- `ExpiresAt time.Time`
  - Absolute expiry timestamp embedded into the packaged token. If zero, the library deterministically defaults to `time.Now().UTC() + DefaultPackagedExpiry`.

Notes:
- If you pass no `Options` or a nil `Options`, the library uses defaults via an internal helper.
- Binding only applies when `Options.Request` is non-nil and the corresponding `Bind*` flag is true.

## Expiry
Tokens are packaged with an absolute expiry timestamp. During validation, the token is rejected if it is expired.

- Default expiry window: `DefaultPackagedExpiry` (15 minutes) when `Options.ExpiresAt` is zero.
- You can override `ExpiresAt` to any absolute UTC time when generating the token.

## Binding Behavior Examples
- Path binding (`BindPath: true`): tokens generated for `/submit` will not validate for `/other`.
- Method binding (`BindMethod: true`): tokens generated for `POST` will not validate for `GET`.
- IP or User-Agent binding: tokens will only validate when the client presents the same IP or UA as during generation.

## API
```go
// Generate a new CSRF token (opaque string) with optional bindings and expiry.
func TokenGenerate(secret string, opts ...*Options) string

// Validate a token previously produced by TokenGenerate.
// Unpacks the token, checks expiry, rebuilds the plaintext from secret + bound attributes,
// and bcrypt-compares.
func TokenValidate(csrfToken string, secret string, opts ...*Options) bool
```

## Security Considerations
- Use a strong, application-specific `secret` and keep it confidential.
- Choose bindings appropriate for your deployment (e.g., be mindful of proxies/CDNs when enabling `BindIP`).
- Prefer HTTPS to protect tokens in transit.

## Testing
Run the test suite:
```
go test ./...
```
