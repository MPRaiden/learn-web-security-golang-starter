package pawpal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func CreateReference(orderID, totalCents int64, apiKey string) string {
	signature := hmac.New(sha256.New, []byte(apiKey))
	_, _ = fmt.Fprintf(signature, "%d:%d", orderID, totalCents)
	return fmt.Sprintf("pawpal_%d_%s", orderID, hex.EncodeToString(signature.Sum(nil))[:16])
}
