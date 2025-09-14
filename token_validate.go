package csrf

import (
	"strconv"
	"time"

	"github.com/dracory/str"
)

func TokenValidate(csrfToken string, secret string, opts ...*Options) bool {
	// Validate packaged tokens of the form "<bcrypt-hash>:<expiresUnix>".
	var o *Options
	if len(opts) > 0 {
		o = opts[0]
	}

	hash, expUnix, err := unbox(csrfToken)
	if err != nil {
		return false
	}
	if time.Now().UTC().Unix() > expUnix {
		return false // expired
	}

	augmented := buildAugmentedSecret(secret, o)
	plaintext := augmented + "|exp:" + strconv.FormatInt(expUnix, 10)
	tokenTruncated := truncateToBytes(plaintext, 72)
	return str.BcryptHashCompare(tokenTruncated, hash)
}
