package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	applicationOrigin   = "http://localhost:3030"
	maximumResponseSize = 64 * 1024
)

type checkResult struct {
	SignupFormHasHoneypot        bool `json:"signupFormHasHoneypot"`
	LowRiskAllowed               bool `json:"lowRiskAllowed"`
	MediumRiskChallenged         bool `json:"mediumRiskChallenged"`
	HighRiskBlocked              bool `json:"highRiskBlocked"`
	ChallengedAccountsNotCreated bool `json:"challengedAccountsNotCreated"`
}

type signupSignals struct {
	Honeypot              string
	UserAgent             string
	Accept                string
	AcceptLanguage        string
	IncludeUserAgent      bool
	IncludeAccept         bool
	IncludeAcceptLanguage bool
}

type signupResponse struct {
	StatusCode int
	Location   string
	RetryAfter string
	Body       string
}

func main() {
	result, err := checkBotDetection(context.Background(), applicationOrigin)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}

func checkBotDetection(ctx context.Context, origin string) (checkResult, error) {
	httpClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	formHasHoneypot, err := signupFormHasHoneypot(ctx, httpClient, origin)
	if err != nil {
		return checkResult{}, err
	}
	randomEmailSuffix, err := randomSuffix()
	if err != nil {
		return checkResult{}, err
	}

	standardSignals := signupSignals{
		UserAgent:             "Mozilla/5.0",
		Accept:                "text/html",
		AcceptLanguage:        "en-US",
		IncludeUserAgent:      true,
		IncludeAccept:         true,
		IncludeAcceptLanguage: true,
	}
	lowRiskResponse, err := submitSignup(ctx, httpClient, origin, "low-"+randomEmailSuffix+"@example.com", standardSignals)
	if err != nil {
		return checkResult{}, err
	}

	headlessSignals := standardSignals
	headlessSignals.UserAgent = "Mozilla/5.0 HeadlessChrome/123.0"
	mediumEmail := "medium-" + randomEmailSuffix + "@example.com"
	mediumResponse, err := submitSignup(ctx, httpClient, origin, mediumEmail, headlessSignals)
	if err != nil {
		return checkResult{}, err
	}
	automationSignals := standardSignals
	automationSignals.UserAgent = "curl/8.7.1"
	automationResponse, err := submitSignup(ctx, httpClient, origin, "automation-"+randomEmailSuffix+"@example.com", automationSignals)
	if err != nil {
		return checkResult{}, err
	}
	missingHeaderSignals := signupSignals{
		IncludeUserAgent: true,
		IncludeAccept:    true,
	}
	missingHeaderResponse, err := submitSignup(ctx, httpClient, origin, "missing-"+randomEmailSuffix+"@example.com", missingHeaderSignals)
	if err != nil {
		return checkResult{}, err
	}

	honeypotSignals := standardSignals
	honeypotSignals.Honeypot = "https://spam.example"
	highEmail := "high-" + randomEmailSuffix + "@example.com"
	highResponse, err := submitSignup(ctx, httpClient, origin, highEmail, honeypotSignals)
	if err != nil {
		return checkResult{}, err
	}
	automationHighSignals := automationSignals
	automationHighSignals.IncludeAcceptLanguage = false
	automationHighResponse, err := submitSignup(ctx, httpClient, origin, "automation-high-"+randomEmailSuffix+"@example.com", automationHighSignals)
	if err != nil {
		return checkResult{}, err
	}

	mediumRetryResponse, err := submitSignup(ctx, httpClient, origin, mediumEmail, standardSignals)
	if err != nil {
		return checkResult{}, err
	}
	highRetryResponse, err := submitSignup(ctx, httpClient, origin, highEmail, standardSignals)
	if err != nil {
		return checkResult{}, err
	}

	return checkResult{
		SignupFormHasHoneypot: formHasHoneypot,
		LowRiskAllowed:        signupAllowed(lowRiskResponse),
		MediumRiskChallenged: signupChallenged(mediumResponse) &&
			signupChallenged(automationResponse) && signupChallenged(missingHeaderResponse),
		HighRiskBlocked:              signupBlocked(highResponse) && signupBlocked(automationHighResponse),
		ChallengedAccountsNotCreated: signupAllowed(mediumRetryResponse) && signupAllowed(highRetryResponse),
	}, nil
}

func signupFormHasHoneypot(ctx context.Context, httpClient *http.Client, origin string) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/signup", nil)
	if err != nil {
		return false, fmt.Errorf("create sign-up form request: %w", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return false, fmt.Errorf("request sign-up form: %w", err)
	}
	responseBody, err := readResponseBody(response)
	if err != nil {
		return false, fmt.Errorf("read sign-up form: %w", err)
	}
	return response.StatusCode == http.StatusOK &&
		strings.Contains(responseBody, `name="companyWebsite"`) &&
		strings.Contains(responseBody, `tabindex="-1"`) &&
		strings.Contains(responseBody, `autocomplete="off"`), nil
}

func submitSignup(ctx context.Context, httpClient *http.Client, origin, email string, signals signupSignals) (signupResponse, error) {
	formValues := url.Values{
		"companyWebsite": {signals.Honeypot},
		"displayName":    {"Bot Risk Student"},
		"email":          {email},
		"password":       {"password123"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/signup", strings.NewReader(formValues.Encode()))
	if err != nil {
		return signupResponse{}, fmt.Errorf("create sign-up request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	setOptionalHeader(request.Header, "User-Agent", signals.UserAgent, signals.IncludeUserAgent)
	setOptionalHeader(request.Header, "Accept", signals.Accept, signals.IncludeAccept)
	setOptionalHeader(request.Header, "Accept-Language", signals.AcceptLanguage, signals.IncludeAcceptLanguage)

	response, err := httpClient.Do(request)
	if err != nil {
		return signupResponse{}, fmt.Errorf("submit sign-up request: %w", err)
	}
	responseBody, err := readResponseBody(response)
	if err != nil {
		return signupResponse{}, fmt.Errorf("read sign-up response: %w", err)
	}
	return signupResponse{
		StatusCode: response.StatusCode,
		Location:   response.Header.Get("Location"),
		RetryAfter: response.Header.Get("Retry-After"),
		Body:       responseBody,
	}, nil
}

func setOptionalHeader(header http.Header, name, value string, include bool) {
	if include {
		header[name] = []string{value}
	}
}

func readResponseBody(response *http.Response) (string, error) {
	defer response.Body.Close()
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseSize))
	if err != nil {
		return "", err
	}
	return string(responseBytes), nil
}

func signupAllowed(response signupResponse) bool {
	return response.StatusCode == http.StatusFound && response.Location == "/account"
}

func signupChallenged(response signupResponse) bool {
	return response.StatusCode == http.StatusForbidden && strings.Contains(response.Body, "Additional verification required")
}

func signupBlocked(response signupResponse) bool {
	return response.StatusCode == http.StatusTooManyRequests && response.RetryAfter == "60" && strings.Contains(response.Body, "Request could not be completed")
}

func randomSuffix() (string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate random email suffix: %w", err)
	}
	return hex.EncodeToString(randomBytes), nil
}
