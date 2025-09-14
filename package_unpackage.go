package csrf

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// packageToken combines a hash and an expiry timestamp into the packaged token format
// "<hash>:<expiresUnix>". It performs no validation.
func packageToken(hash string, expiresAt time.Time) string {
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC()
	} else {
		expiresAt = time.Now().UTC().Add(DefaultPackagedExpiry)
	}

	return hash + ":" + strconv.FormatInt(expiresAt.Unix(), 10)
}

// unpackageToken parses a packaged token of the form "<hash>:<expiresUnix>" and returns
// the hash and the parsed expiry. It does not check whether the token is expired.
func unpackageToken(packaged string) (hash string, expires time.Time, err error) {
	idx := strings.LastIndex(packaged, ":")

	if idx <= 0 || idx >= len(packaged)-1 {
		return "", time.Time{}, fmt.Errorf("invalid packaged token format")
	}

	hash = packaged[:idx]
	expStr := packaged[idx+1:]
	v, perr := strconv.ParseInt(expStr, 10, 64)
	if perr != nil {
		return "", time.Time{}, perr
	}

	return hash, time.Unix(v, 0).UTC(), nil
}
