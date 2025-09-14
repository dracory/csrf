package csrf

import (
	"time"

	"github.com/dracory/str"
)

// TokenValidate validates a packaged CSRF token produced by TokenGenerate.
//
// This function internally unpacks the token format used by the generator.
// The function will:
//  1. Unpackage the token and parse the embedded expiry timestamp.
//  2. Reject the token if it is expired relative to time.Now().UTC().
//  3. Rebuild the plaintext using the provided secret plus any request-bound
//     attributes enabled via Options (e.g., BindIP, BindUserAgent, BindPath, BindMethod).
//  4. Compare the bcrypt hash against the rebuilt plaintext (truncated to 72 bytes).
//
// If opts is omitted or ExpiresAt is zero, a default expiry of now + DefaultPackagedExpiry
// is assumed for rebuilding the plaintext, keeping generation and validation consistent.
func TokenValidate(csrfToken string, secret string, opts ...*Options) bool {
	o := getOptionsOrDefault(opts...)

	hash, expAt, err := unpackageToken(csrfToken)
	if err != nil {
		return false
	}
	now := time.Now().UTC()
	if now.After(expAt) {
		return false // expired
	}

	augmented := buildAugmentedSecret(secret, o)
	plaintext := augmented
	tokenTruncated := truncateToBytes(plaintext, 72)
	return str.BcryptHashCompare(tokenTruncated, hash)
}
