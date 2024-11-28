package csrf

import (
	"github.com/dromara/carbon/v2"
	"github.com/gouniverse/utils"
)

func TokenGenerate(secret string) string {
	secret += CSRF_TOKEN_SECRET
	token := carbon.Now(carbon.UTC).Format("Ymd") + secret
	tokenTruncated := truncateToBytes(token, 72) // max 72 bytes
	csrfToken, _ := utils.StrToBcryptHash(tokenTruncated)
	return csrfToken
}
