package csrf

import (
	"github.com/dracory/str"
	"strconv"
	"time"
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
	}

	var exp time.Time
	if o != nil && !o.ExpiresAt.IsZero() {
		exp = o.ExpiresAt.UTC()
	} else {
		exp = time.Now().UTC().Add(DefaultPackagedExpiry)
	}
	augmented := buildAugmentedSecret(secret, o)
	expUnix := strconv.FormatInt(exp.Unix(), 10)
	plaintext := augmented + "|exp:" + expUnix
	tokenTruncated := truncateToBytes(plaintext, 72)
	bcryptHash, _ := str.ToBcryptHash(tokenTruncated)
	return bcryptHash + ":" + expUnix
}
