package csrf

import (
	"github.com/dracory/str"
	"github.com/dromara/carbon/v2"
)

func TokenGenerate(secret string) string {
	return TokenGenerateWith(secret, nil)
}

// TokenGenerateWith generates a CSRF token from the provided secret and optional options.
// If opts is nil, defaults to day-level granularity and no request binding.
func TokenGenerateWith(secret string, opts *Options) string {
	augmented := buildAugmentedSecret(secret, opts)
	timeFmt := buildTimeFormat(opts)
	token := carbon.Now(carbon.UTC).Format(timeFmt) + augmented
	tokenTruncated := truncateToBytes(token, 72) // max 72 bytes to respect bcrypt input limit
	csrfToken, _ := str.ToBcryptHash(tokenTruncated)
	return csrfToken
}
