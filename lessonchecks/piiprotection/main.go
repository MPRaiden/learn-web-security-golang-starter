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
	"strconv"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/logging"
)

var csrfPattern = regexp.MustCompile(`name="csrfToken"\s+type="hidden"\s+value="([^"]+)"`)

type result struct {
	ShippingEncryptedAtRest  bool `json:"shippingEncryptedAtRest"`
	InternalNotesExcludePII  bool `json:"internalNotesExcludePII"`
	SupportCanReadShipping   bool `json:"supportCanReadShipping"`
	ApplicationLogsRedactPII bool `json:"applicationLogsRedactPII"`
	CentralPolicyRedactsPII  bool `json:"centralPolicyRedactsPII"`
}

func main() {
	ctx := context.Background()
	logPath := filepath.Join("data", "bearly-secure.log")
	logOffset := fileSize(logPath)
	databaseConnection, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		writeResult(result{})
		return
	}
	defer databaseConnection.Close()

	mabelClient, err := authenticatedClient(ctx, "mabel@example.com")
	if err != nil {
		writeResult(result{})
		return
	}
	csrfToken, err := csrfToken(ctx, mabelClient)
	if err != nil || submitCartItem(ctx, mabelClient, csrfToken) != http.StatusFound {
		writeResult(result{})
		return
	}
	shipping := url.Values{
		"csrfToken": {csrfToken}, "shippingName": {"Cipher Bear"},
		"shippingAddress": {"12 Encryption Lane"}, "shippingCity": {"Lockbox"},
		"shippingRegion": {"VA"}, "shippingPostalCode": {"22030"},
	}
	checkoutResponse, err := submitForm(ctx, mabelClient, "/checkout", shipping)
	if err != nil {
		writeResult(result{})
		return
	}
	checkoutResponse.Body.Close()
	orderID := latestOrderID(ctx, databaseConnection, 1)
	var encryptedShipping sql.NullString
	var adminNotes string
	_ = databaseConnection.QueryRowContext(ctx, "SELECT shipping_details_encrypted, admin_notes FROM orders WHERE id = ?", orderID).Scan(&encryptedShipping, &adminNotes)

	var envelope struct {
		KeyVersion string `json:"keyVersion"`
	}
	encryptedAtRest := checkoutResponse.StatusCode == http.StatusFound && encryptedShipping.Valid &&
		json.Unmarshal([]byte(encryptedShipping.String), &envelope) == nil && envelope.KeyVersion == "v1" &&
		!containsAny(encryptedShipping.String, "Cipher Bear", "12 Encryption Lane", "Lockbox", "22030")

	supportClient, _ := authenticatedClient(ctx, "sancho@example.com")
	supportResponse, supportErr := request(ctx, supportClient, "/support/orders/"+strconv.FormatInt(orderID, 10))
	var supportBody []byte
	if supportErr == nil {
		supportBody, _ = io.ReadAll(supportResponse.Body)
		supportResponse.Body.Close()
	}
	appendedLog := readAfter(logPath, logOffset)

	writeResult(result{
		ShippingEncryptedAtRest:  encryptedAtRest,
		InternalNotesExcludePII:  adminNotes == "PawPal redirect approved.",
		SupportCanReadShipping:   supportErr == nil && supportResponse.StatusCode == http.StatusOK && containsAll(string(supportBody), "Cipher Bear", "12 Encryption Lane", "Lockbox", "22030"),
		ApplicationLogsRedactPII: !containsAny(string(appendedLog), "mabel@example.com", "Cipher Bear", "12 Encryption Lane", "Lockbox", "22030"),
		CentralPolicyRedactsPII:  centralPolicyRedactsPII(),
	})
}

func centralPolicyRedactsPII() bool {
	directory, err := os.MkdirTemp("", "pii-redaction-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(directory)
	logPath := filepath.Join(directory, "probe.log")
	logger, err := logging.Open(logPath)
	if err != nil {
		return false
	}
	fields := map[string]any{
		"email": "customer@example.com", "shippingName": "Cipher Bear",
		"shippingAddress": "12 Encryption Lane", "shippingCity": "Lockbox",
		"shippingRegion": "VA", "shippingPostalCode": "22030",
		"originalName": "customer-tax-document.pdf", "userId": 42,
	}
	if logger.Event("pii_probe", fields) != nil || logger.Close() != nil {
		return false
	}
	contents, err := os.ReadFile(logPath)
	if err != nil || containsAny(string(contents), "customer@example.com", "Cipher Bear", "12 Encryption Lane", "Lockbox", "22030", "customer-tax-document.pdf") {
		return false
	}
	var record map[string]any
	if json.Unmarshal(contents, &record) != nil || record["userId"] != float64(42) {
		return false
	}
	for name := range fields {
		if name != "userId" && record[name] != "[REDACTED]" {
			return false
		}
	}
	return true
}

func authenticatedClient(ctx context.Context, email string) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := submitForm(ctx, client, "/login", url.Values{"email": {email}, "password": {"password123"}, "returnTo": {"/"}})
	if err != nil || response.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("log in %s", email)
	}
	response.Body.Close()
	return client, nil
}

func csrfToken(ctx context.Context, client *http.Client) (string, error) {
	response, err := request(ctx, client, "/")
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

func submitCartItem(ctx context.Context, client *http.Client, token string) int {
	response, err := submitForm(ctx, client, "/cart/items", url.Values{
		"csrfToken": {token}, "productId": {"1"}, "quantity": {"1"},
	})
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

func request(ctx context.Context, client *http.Client, path string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin()+path, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(request)
}

func latestOrderID(ctx context.Context, databaseConnection *sql.DB, userID int64) int64 {
	var orderID int64
	_ = databaseConnection.QueryRowContext(ctx, "SELECT id FROM orders WHERE user_id = ? ORDER BY id DESC LIMIT 1", userID).Scan(&orderID)
	return orderID
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func readAfter(path string, offset int64) []byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	_, _ = file.Seek(offset, io.SeekStart)
	contents, _ := io.ReadAll(file)
	return contents
}

func containsAny(value string, expected ...string) bool {
	for _, item := range expected {
		if strings.Contains(value, item) {
			return true
		}
	}
	return false
}

func containsAll(value string, expected ...string) bool {
	for _, item := range expected {
		if !strings.Contains(value, item) {
			return false
		}
	}
	return true
}

func origin() string {
	return strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
