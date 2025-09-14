package csrf

import (
	"time"

	"github.com/dracory/str"
)

// TokenGenerate generates a CSRF token from the provided secret.
// Optional opts[0] can customize binding and expiry behavior. This function always returns
// a packaged token in the form "<bcrypt-hash>:<expiresUnix>" and binds the expiry into the
// hash input as "|exp:<expiresUnix>" to prevent tampering. If ExpiresAt is zero, the expiry
// defaults to now (UTC) + DefaultPackagedExpiry.
func TokenGenerate(secret string, opts ...*Options) string {
	var o *Options
	if len(opts) > 0 {
		o = opts[0]
	} else {
		o = &Options{
			ExpiresAt: time.Now().UTC().Add(DefaultPackagedExpiry),
		}
	}

	augmented := buildAugmentedSecret(secret, o)
	tokenTruncated := truncateToBytes(augmented, 72)
	bcryptHash, _ := str.ToBcryptHash(tokenTruncated)
	return packageToken(bcryptHash, o.ExpiresAt)
}
