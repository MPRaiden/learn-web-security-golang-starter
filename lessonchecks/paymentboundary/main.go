package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
)

const checkoutToken = "pawpal_tok_bearly_secure_demo"

var csrfPattern = regexp.MustCompile(`name="csrfToken"\s+type="hidden"\s+value="([^"]+)"`)

type result struct {
	RawFieldsRejectedSeparately bool `json:"rawFieldsRejectedSeparately"`
	MissingTokenRejected        bool `json:"missingTokenRejected"`
	ForgedTokenRejected         bool `json:"forgedTokenRejected"`
	RejectedRequestsHaveNoOrder bool `json:"rejectedRequestsHaveNoOrder"`
	ServerAmountUsed            bool `json:"serverAmountUsed"`
	ApprovedReferenceStored     bool `json:"approvedReferenceStored"`
	FreshAttemptReferenceUsed   bool `json:"freshAttemptReferenceUsed"`
	PaymentTokenRedacted        bool `json:"paymentTokenRedacted"`
}

func main() {
	ctx := context.Background()
	databaseConnection, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		writeResult(result{})
		return
	}
	defer databaseConnection.Close()
	client, err := authenticatedClient(ctx)
	if err != nil {
		writeResult(result{})
		return
	}
	csrfToken, err := findCSRFToken(ctx, client)
	if err != nil {
		writeResult(result{})
		return
	}

	initialOrders := countOrders(ctx, databaseConnection)
	rawFieldsRejected := true
	for name, value := range map[string]string{"cardNumber": "4111111111111111", "cvv": "123", "expiry": "12/30"} {
		resetCart(ctx, databaseConnection)
		values := checkoutValues(csrfToken, checkoutToken)
		values.Set(name, value)
		rawFieldsRejected = rawFieldsRejected && submitCheckout(ctx, client, values) == http.StatusBadRequest
	}
	afterRawFields := countOrders(ctx, databaseConnection)

	resetCart(ctx, databaseConnection)
	missingValues := checkoutValues(csrfToken, "")
	missingValues.Del("paymentToken")
	missingRejected := submitCheckout(ctx, client, missingValues) == http.StatusBadRequest
	afterMissing := countOrders(ctx, databaseConnection)

	resetCart(ctx, databaseConnection)
	forgedRejected := submitCheckout(ctx, client, checkoutValues(csrfToken, "forged-token")) == http.StatusBadRequest
	afterForged := countOrders(ctx, databaseConnection)

	resetCart(ctx, databaseConnection)
	validValues := checkoutValues(csrfToken, checkoutToken)
	validValues.Set("amountCents", "1")
	validStatus := submitCheckout(ctx, client, validValues)
	firstPayment := latestPayment(ctx, databaseConnection)

	resetCart(ctx, databaseConnection)
	secondStatus := submitCheckout(ctx, client, checkoutValues(csrfToken, checkoutToken))
	secondPayment := latestPayment(ctx, databaseConnection)

	writeResult(result{
		RawFieldsRejectedSeparately: rawFieldsRejected,
		MissingTokenRejected:        missingRejected,
		ForgedTokenRejected:         forgedRejected,
		RejectedRequestsHaveNoOrder: afterRawFields == initialOrders && afterMissing == initialOrders && afterForged == initialOrders,
		ServerAmountUsed:            validStatus == http.StatusFound && firstPayment.totalCents == 2499,
		ApprovedReferenceStored:     strings.HasPrefix(firstPayment.reference, "pawpal_txn_") && firstPayment.status == "approved",
		FreshAttemptReferenceUsed:   secondStatus == http.StatusFound && secondPayment.reference != "" && secondPayment.reference != firstPayment.reference,
		PaymentTokenRedacted:        paymentTokenRedacted(),
	})
}

type paymentRecord struct {
	reference  string
	status     string
	totalCents int64
}

func latestPayment(ctx context.Context, databaseConnection *sql.DB) paymentRecord {
	var payment paymentRecord
	_ = databaseConnection.QueryRowContext(ctx, "SELECT payment_reference, payment_status, total_cents FROM orders WHERE user_id = 1 ORDER BY id DESC LIMIT 1").Scan(&payment.reference, &payment.status, &payment.totalCents)
	return payment
}

func countOrders(ctx context.Context, databaseConnection *sql.DB) int {
	var count int
	_ = databaseConnection.QueryRowContext(ctx, "SELECT COUNT(*) FROM orders").Scan(&count)
	return count
}

func resetCart(ctx context.Context, databaseConnection *sql.DB) {
	_, _ = databaseConnection.ExecContext(ctx, "DELETE FROM cart_items WHERE user_id = 1")
	_, _ = databaseConnection.ExecContext(ctx, "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (1, 1, 1)")
}

func checkoutValues(csrfToken, paymentToken string) url.Values {
	return url.Values{
		"csrfToken": {csrfToken}, "shippingName": {"Payment Bear"},
		"shippingAddress": {"12 Hosted Lane"}, "shippingCity": {"Lockbox"},
		"shippingRegion": {"VA"}, "shippingPostalCode": {"22030"},
		"paymentToken": {paymentToken},
	}
}

func authenticatedClient(ctx context.Context) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := submitForm(ctx, client, "/login", url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/"},
	})
	if err != nil || response.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("log in")
	}
	response.Body.Close()
	return client, nil
}

func findCSRFToken(ctx context.Context, client *http.Client) (string, error) {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin()+"/", nil)
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	match := csrfPattern.FindSubmatch(body)
	if err != nil || len(match) != 2 {
		return "", fmt.Errorf("find CSRF token")
	}
	return string(match[1]), nil
}

func submitCheckout(ctx context.Context, client *http.Client, values url.Values) int {
	response, err := submitForm(ctx, client, "/checkout", values)
	if err != nil {
		return 0
	}
	defer response.Body.Close()
	return response.StatusCode
}

func submitForm(ctx context.Context, client *http.Client, path string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin()+path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin())
	return client.Do(request)
}

func paymentTokenRedacted() bool {
	directory, err := os.MkdirTemp("", "payment-redaction-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "probe.log")
	logger, err := logging.Open(path)
	if err != nil {
		return false
	}
	if logger.Event("payment_probe", map[string]any{"paymentToken": checkoutToken, "orderId": 42}) != nil || logger.Close() != nil {
		return false
	}
	contents, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(contents), checkoutToken) {
		return false
	}
	var record map[string]any
	return json.Unmarshal(contents, &record) == nil && record["paymentToken"] == "[REDACTED]" && record["orderId"] == float64(42)
}

func origin() string {
	return strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
