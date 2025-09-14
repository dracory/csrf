package csrf

import (
	"github.com/dracory/str"
	"github.com/dromara/carbon/v2"
)

func TokenValidate(csrfToken string, secret string) bool {
	return TokenValidateWith(csrfToken, secret, nil)
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
