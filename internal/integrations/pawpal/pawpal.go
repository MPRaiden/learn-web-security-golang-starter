package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if len(providedKey) != len(expectedKey) {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}

	pl, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	num, ok := pl["orderId"].(float64)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	if num <= 0 || pl["status"] != "approved" || num != math.Trunc(num) {
		return WebhookVerification{Outcome: WebhookMalformed}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(num)}
}
