package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	headerNoncePattern = regexp.MustCompile(`nonce-([^']+)`)
	scriptNoncePattern = regexp.MustCompile(`<script nonce="([^"]+)">`)
)

type results struct {
	NoncePresentAndMatches    bool `json:"noncePresentAndMatches"`
	NonceFreshAcrossResponses bool `json:"nonceFreshAcrossResponses"`
	UnsafeInlineAbsent        bool `json:"unsafeInlineAbsent"`
	BaselinePolicyPreserved   bool `json:"baselinePolicyPreserved"`
}

func main() {
	output, err := checkCSPNonces(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkCSPNonces(ctx context.Context) (results, error) {
	applicationOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if applicationOrigin == "" {
		applicationOrigin = "http://localhost:3030"
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return results{}, err
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	loginResponse, err := postForm(ctx, client, applicationOrigin+"/login", applicationOrigin, url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/pawpal/processing/1"},
	})
	if err != nil {
		return results{}, err
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusFound {
		return results{}, fmt.Errorf("log in: status %d", loginResponse.StatusCode)
	}

	processingPolicy, processingBody, err := getPage(ctx, client, applicationOrigin+"/pawpal/processing/1")
	if err != nil {
		return results{}, err
	}
	firstAccountPolicy, _, err := getPage(ctx, client, applicationOrigin+"/account")
	if err != nil {
		return results{}, err
	}
	secondAccountPolicy, _, err := getPage(ctx, client, applicationOrigin+"/account")
	if err != nil {
		return results{}, err
	}

	processingNonce := submatch(headerNoncePattern, processingPolicy)
	scriptNonce := html.UnescapeString(submatch(scriptNoncePattern, processingBody))
	firstAccountNonce := submatch(headerNoncePattern, firstAccountPolicy)
	secondAccountNonce := submatch(headerNoncePattern, secondAccountPolicy)
	return results{
		NoncePresentAndMatches: processingNonce != "" && processingNonce == scriptNonce,
		NonceFreshAcrossResponses: processingNonce != "" && firstAccountNonce != "" && secondAccountNonce != "" &&
			processingNonce != firstAccountNonce && firstAccountNonce != secondAccountNonce,
		UnsafeInlineAbsent: !strings.Contains(processingPolicy, "'unsafe-inline'") &&
			!strings.Contains(firstAccountPolicy, "'unsafe-inline'") &&
			!strings.Contains(secondAccountPolicy, "'unsafe-inline'"),
		BaselinePolicyPreserved: hasBaselinePolicy(processingPolicy) &&
			hasBaselinePolicy(firstAccountPolicy) &&
			hasBaselinePolicy(secondAccountPolicy),
	}, nil
}

func hasBaselinePolicy(policy string) bool {
	directives := []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"frame-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	}
	for _, directive := range directives {
		if !strings.Contains(policy, directive) {
			return false
		}
	}
	return true
}

func getPage(ctx context.Context, client *http.Client, endpoint string) (string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return "", "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("get %s: status %d", endpoint, response.StatusCode)
	}
	return response.Header.Get("Content-Security-Policy"), string(body), nil
}

func postForm(ctx context.Context, client *http.Client, endpoint, applicationOrigin string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	return client.Do(request)
}

func submatch(pattern *regexp.Regexp, value string) string {
	match := pattern.FindStringSubmatch(value)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}
