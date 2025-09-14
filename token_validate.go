package csrf

import (
	"time"

	"github.com/dracory/str"
)

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
