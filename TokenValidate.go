package csrf

import (
	"github.com/dromara/carbon/v2"
	"github.com/gouniverse/utils"
)

func TokenValidate(csrfToken string, secret string) bool {
	secret += CSRF_TOKEN_SECRET
	token := carbon.Now(carbon.UTC).Format("Ymd") + secret
	tokenTruncated := truncateToBytes(token, 72) // max 72 bytes
	isOk := utils.StrToBcryptHashCompare(tokenTruncated, csrfToken)
	return isOk
}
