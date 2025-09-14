package csrf

import (
	"github.com/dracory/str"
	"github.com/dromara/carbon/v2"
	"strconv"
	"strings"
	"time"
)

func TokenValidate(csrfToken string, secret string) bool {
	// Default path validates packaged tokens of the form "<hash>:<expiresUnix>".
	return TokenValidatePackaged(csrfToken, secret, nil)
}

// TokenValidateWith validates the provided CSRF token against the secret and optional options.
// If opts is nil, defaults to day-level granularity and no request binding.
func TokenValidateWith(csrfToken string, secret string, opts *Options) bool {
	augmented := buildAugmentedSecret(secret, opts)
	timeFmt := buildTimeFormat(opts)
	token := carbon.Now(carbon.UTC).Format(timeFmt) + augmented
	tokenTruncated := truncateToBytes(token, 72) // max 72 bytes
	isOk := str.BcryptHashCompare(tokenTruncated, csrfToken)
	return isOk
}

// TokenValidatePackaged validates a packaged token in the format "<bcrypt-hash>:<expiresUnix>".
// It first checks the expiry against the current UTC time. It then validates the hash by
// recomputing the plaintext including the expiry ("...|exp:<expiresUnix>") bound into it.
func TokenValidatePackaged(packagedToken string, secret string, opts *Options) bool {
	// Split hash and expiry by the last colon to be robust if future formats add more colons.
	idx := strings.LastIndex(packagedToken, ":")
	if idx <= 0 || idx >= len(packagedToken)-1 {
		return false
	}
	hash := packagedToken[:idx]
	expStr := packagedToken[idx+1:]
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().UTC().Unix() > expUnix {
		return false // expired
	}

	augmented := buildAugmentedSecret(secret, opts)
	plaintext := augmented + "|exp:" + expStr
	tokenTruncated := truncateToBytes(plaintext, 72)
	return str.BcryptHashCompare(tokenTruncated, hash)
}
