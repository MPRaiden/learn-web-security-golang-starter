package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var csrfTokenPattern = regexp.MustCompile(`name="csrfToken"[^>]*value="([^"]+)"`)

type results struct {
	TokensRendered                        bool `json:"tokensRendered"`
	SessionTokensDistinct                 bool `json:"sessionTokensDistinct"`
	AllProtectedRoutesRejectInvalidTokens bool `json:"allProtectedRoutesRejectInvalidTokens"`
	MissingTokenRejected                  bool `json:"missingTokenRejected"`
	CrossSessionTokenRejected             bool `json:"crossSessionTokenRejected"`
	ValidTokensAccepted                   bool `json:"validTokensAccepted"`
	RejectedRequestsLeaveStateUnchanged   bool `json:"rejectedRequestsLeaveStateUnchanged"`
}

type formProbe struct {
	path   string
	values url.Values
	status int
}

func main() {
	output, err := checkCSRFTokens(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkCSRFTokens(ctx context.Context) (results, error) {
	applicationOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if applicationOrigin == "" {
		applicationOrigin = "http://localhost:3030"
	}
	firstClient, err := newClient()
	if err != nil {
		return results{}, err
	}
	if err := login(ctx, firstClient, applicationOrigin); err != nil {
		return results{}, err
	}
	firstToken, accountPage, err := tokenFromPage(ctx, firstClient, applicationOrigin+"/account")
	if err != nil {
		return results{}, err
	}
	productToken, _, err := tokenFromPage(ctx, firstClient, applicationOrigin+"/products/1")
	if err != nil {
		return results{}, err
	}
	reviewToken, _, err := tokenFromPage(ctx, firstClient, applicationOrigin+"/account/reviews/1/edit")
	if err != nil {
		return results{}, err
	}

	secondClient, err := newClient()
	if err != nil {
		return results{}, err
	}
	if err := login(ctx, secondClient, applicationOrigin); err != nil {
		return results{}, err
	}
	secondToken, _, err := tokenFromPage(ctx, secondClient, applicationOrigin+"/account")
	if err != nil {
		return results{}, err
	}

	invalidProbes := []formProbe{
		{path: "/account/totp/disable", values: url.Values{}},
		{path: "/account/email", values: url.Values{"email": {"mabel+csrf@example.com"}, "currentPassword": {"password123"}}},
		{path: "/account/reviews/1", values: url.Values{"rating": {"1"}, "body": {"invalid-update"}}},
		{path: "/account/reviews/1/delete", values: url.Values{}},
		{path: "/cart/items", values: url.Values{"productId": {"1"}, "quantity": {"1"}}},
		{path: "/cart/items/1", values: url.Values{"quantity": {"2"}}},
		{path: "/checkout", values: checkoutValues()},
		{path: "/products/3/reviews", values: url.Values{"rating": {"1"}, "body": {"invalid-create"}}},
	}
	invalidStatuses := make([]int, 0, len(invalidProbes))
	for _, probe := range invalidProbes {
		probe.values.Set("csrfToken", "invalid-token")
		status, err := submitForm(ctx, firstClient, applicationOrigin+probe.path, applicationOrigin, probe.values)
		if err != nil {
			return results{}, err
		}
		invalidStatuses = append(invalidStatuses, status)
	}

	missingStatus, err := submitForm(ctx, firstClient, applicationOrigin+"/cart/items", applicationOrigin, url.Values{
		"productId": {"1"}, "quantity": {"1"},
	})
	if err != nil {
		return results{}, err
	}
	crossSessionStatus, err := submitForm(ctx, firstClient, applicationOrigin+"/cart/items", applicationOrigin, url.Values{
		"csrfToken": {secondToken}, "productId": {"1"}, "quantity": {"1"},
	})
	if err != nil {
		return results{}, err
	}

	cartBeforeValid, err := getPage(ctx, firstClient, applicationOrigin+"/cart")
	if err != nil {
		return results{}, err
	}
	productAfterRejected, err := getPage(ctx, firstClient, applicationOrigin+"/products/3")
	if err != nil {
		return results{}, err
	}
	accountAfterRejected, err := getPage(ctx, firstClient, applicationOrigin+"/account")
	if err != nil {
		return results{}, err
	}

	validProbes := []formProbe{
		{path: "/account/totp/disable", values: url.Values{}, status: http.StatusFound},
		{path: "/account/email", values: url.Values{"email": {"mabel@example.com"}, "currentPassword": {"password123"}}, status: http.StatusFound},
		{path: "/account/reviews/1", values: url.Values{"rating": {"5"}, "body": {"valid update"}}, status: http.StatusFound},
		{path: "/account/reviews/1/delete", values: url.Values{}, status: http.StatusFound},
		{path: "/cart/items", values: url.Values{"productId": {"1"}, "quantity": {"1"}}, status: http.StatusFound},
		{path: "/cart/items/1", values: url.Values{"quantity": {"2"}}, status: http.StatusFound},
		{path: "/products/3/reviews", values: url.Values{"rating": {"5"}, "body": {"valid create"}}, status: http.StatusFound},
	}
	validStatuses := make([]int, 0, len(validProbes)+1)
	for _, probe := range validProbes {
		probe.values.Set("csrfToken", firstToken)
		status, err := submitForm(ctx, firstClient, applicationOrigin+probe.path, applicationOrigin, probe.values)
		if err != nil {
			return results{}, err
		}
		validStatuses = append(validStatuses, status)
	}
	cartToken, _, err := tokenFromPage(ctx, firstClient, applicationOrigin+"/cart")
	if err != nil {
		return results{}, err
	}
	checkoutToken, _, err := tokenFromPage(ctx, firstClient, applicationOrigin+"/checkout")
	if err != nil {
		return results{}, err
	}
	checkoutForm := checkoutValues()
	checkoutForm.Set("csrfToken", firstToken)
	checkoutStatus, err := submitForm(ctx, firstClient, applicationOrigin+"/checkout", applicationOrigin, checkoutForm)
	if err != nil {
		return results{}, err
	}
	validStatuses = append(validStatuses, checkoutStatus)

	return results{
		TokensRendered:                        nonemptyAndEqual(firstToken, productToken, reviewToken, cartToken, checkoutToken),
		SessionTokensDistinct:                 firstToken != "" && secondToken != "" && firstToken != secondToken,
		AllProtectedRoutesRejectInvalidTokens: allStatusesEqual(invalidStatuses, http.StatusForbidden),
		MissingTokenRejected:                  missingStatus == http.StatusForbidden,
		CrossSessionTokenRejected:             crossSessionStatus == http.StatusForbidden,
		ValidTokensAccepted:                   allStatusesEqual(validStatuses, http.StatusFound),
		RejectedRequestsLeaveStateUnchanged: strings.Contains(cartBeforeValid, "Your cart is empty") &&
			!strings.Contains(productAfterRejected, "invalid-create") &&
			strings.Contains(accountPage, "mabel@example.com") &&
			strings.Contains(accountAfterRejected, "mabel@example.com") &&
			!strings.Contains(accountAfterRejected, "mabel+csrf@example.com"),
	}, nil
}

func newClient() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func login(ctx context.Context, client *http.Client, applicationOrigin string) error {
	status, err := submitForm(ctx, client, applicationOrigin+"/login", applicationOrigin, url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/account"},
	})
	if err != nil {
		return err
	}
	if status != http.StatusFound {
		return fmt.Errorf("log in: status %d", status)
	}
	return nil
}

func tokenFromPage(ctx context.Context, client *http.Client, endpoint string) (string, string, error) {
	body, err := getPage(ctx, client, endpoint)
	if err != nil {
		return "", "", err
	}
	match := csrfTokenPattern.FindStringSubmatch(body)
	if len(match) != 2 {
		return "", body, nil
	}
	return match[1], body, nil
}

func getPage(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("get %s: status %d", endpoint, response.StatusCode)
	}
	return string(body), nil
}

func submitForm(ctx context.Context, client *http.Client, endpoint, applicationOrigin string, values url.Values) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func checkoutValues() url.Values {
	return url.Values{
		"shippingName":       {"Mabel Pines"},
		"shippingAddress":    {"618 Gopher Road"},
		"shippingCity":       {"Gravity Falls"},
		"shippingRegion":     {"OR"},
		"shippingPostalCode": {"97000"},
	}
}

func nonemptyAndEqual(values ...string) bool {
	if len(values) == 0 || values[0] == "" {
		return false
	}
	for _, value := range values[1:] {
		if value != values[0] {
			return false
		}
	}
	return true
}

func allStatusesEqual(statuses []int, expected int) bool {
	if len(statuses) == 0 {
		return false
	}
	for _, status := range statuses {
		if status != expected {
			return false
		}
	}
	return true
}
