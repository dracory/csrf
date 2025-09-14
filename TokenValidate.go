package csrf

import (
	"github.com/dracory/str"
	"github.com/dromara/carbon/v2"
)

func TokenValidate(csrfToken string, secret string) bool {
	secret += CSRF_TOKEN_SECRET
	token := carbon.Now(carbon.UTC).Format("Ymd") + secret
	tokenTruncated := truncateToBytes(token, 72) // max 72 bytes
	isOk := str.BcryptHashCompare(tokenTruncated, csrfToken)
	return isOk
}
