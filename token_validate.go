package csrf

import (
    "time"

    "github.com/dracory/str"
)

func TokenValidate(csrfToken string, secret string, opts ...*Options) bool {
    // Validate packaged tokens of the form "<bcrypt-hash>:<expiresUnix>".
    var o *Options
    if len(opts) > 0 {
        o = opts[0]
    }

    hash, expAt, err := unpackageToken(csrfToken)
    if err != nil {
        return false
    }
    now := time.Now().UTC()
    if now.After(expAt) {
        return false // expired
    }

    augmented := buildAugmentedSecret(secret, o)
    // Generation no longer binds expiry into the hashed plaintext; match that here.
    plaintext := augmented
    tokenTruncated := truncateToBytes(plaintext, 72)
    return str.BcryptHashCompare(tokenTruncated, hash)
}
