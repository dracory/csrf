package csrf

import (
	"github.com/dracory/str"
	"github.com/dromara/carbon/v2"
)

func TokenGenerate(secret string) string {
	secret += CSRF_TOKEN_SECRET
	token := carbon.Now(carbon.UTC).Format("Ymd") + secret
	tokenTruncated := truncateToBytes(token, 72) // max 72 bytes
	csrfToken, _ := str.ToBcryptHash(tokenTruncated)
	return csrfToken
}
