package csrf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// packageToken combines a hash and an expiry timestamp into the packaged token format
// "<hash>:<expiresUnix>" and then encodes the whole string using Crockford Base32.
// It performs no validation.
func packageToken(hash string, expiresAt time.Time) string {
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
	} else {
		expiresAt = time.Now().UTC().Add(DefaultPackagedExpiry)
	}

	raw := hash + ":" + strconv.FormatInt(expiresAt.Unix(), 10)
	return encodeCrockford([]byte(raw))
}

// unpackageToken parses a packaged token of the form "<hash>:<expiresUnix>" and returns
// the hash and the parsed expiry. The input is expected to be Crockford Base32-encoded
// as produced by packageToken. It does not check whether the token is expired.
func unpackageToken(packaged string) (hash string, expires time.Time, err error) {
	decoded, derr := decodeCrockford(packaged)
	if derr != nil {
		return "", time.Time{}, derr
	}
	s := string(decoded)
	idx := strings.LastIndex(s, ":")

	if idx <= 0 || idx >= len(s)-1 {
		return "", time.Time{}, fmt.Errorf("invalid packaged token format")
	}

	hash = s[:idx]
	expStr := s[idx+1:]
	v, perr := strconv.ParseInt(expStr, 10, 64)
	if perr != nil {
		return "", time.Time{}, perr
	}

	return hash, time.Unix(v, 0).UTC(), nil
}
