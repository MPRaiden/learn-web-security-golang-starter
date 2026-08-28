package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const neutralResetMessage = "If an account exists for that email, Bear Mail will send a reset link"

type attempt struct {
	StatusCode int
	Body       string
	RetryAfter string
}

type result struct {
	KnownLoginStatuses            []int `json:"knownLoginStatuses"`
	UnknownLoginStatuses          []int `json:"unknownLoginStatuses"`
	LoginIPStatuses               []int `json:"loginIpStatuses"`
	TOTPIPStatuses                []int `json:"totpIpStatuses"`
	KnownResetStatuses            []int `json:"knownResetStatuses"`
	UnknownResetStatuses          []int `json:"unknownResetStatuses"`
	ResetIPStatuses               []int `json:"resetIpStatuses"`
	LoginLimitBodiesMatch         bool  `json:"loginLimitBodiesMatch"`
	ResetLimitBodiesMatch         bool  `json:"resetLimitBodiesMatch"`
	ResetNeutralBodiesMatch       bool  `json:"resetNeutralBodiesMatch"`
	BlockedAttemptsHaveRetryAfter bool  `json:"blockedAttemptsHaveRetryAfter"`
}

func main() {
	applicationOrigin, configuredOrigin, err := applicationOrigins()
	if err != nil {
		log.Fatal(err)
	}

	loginEmailVariants := []string{
		" MABEL@EXAMPLE.COM ",
		"mabel@example.com",
		"Mabel@Example.Com",
		"mabel@example.com ",
		" Mabel@example.com",
		"MABEL@example.com",
	}
	unknownLoginVariants := make([]string, len(loginEmailVariants))
	for index, email := range loginEmailVariants {
		unknownLoginVariants[index] = strings.Replace(strings.ToLower(email), "mabel", "nobody", 1)
	}
	knownLogin := attemptSeries(applicationOrigin, configuredOrigin, "/login", loginEmailVariants, func(index int) string {
		return fmt.Sprintf("127.32.1.%d", index+1)
	}, url.Values{"password": {"incorrect-password"}, "returnTo": {"/"}})
	unknownLogin := attemptSeries(applicationOrigin, configuredOrigin, "/login", unknownLoginVariants, func(index int) string {
		return fmt.Sprintf("127.32.2.%d", index+1)
	}, url.Values{"password": {"incorrect-password"}, "returnTo": {"/"}})
	loginEmails := make([]string, 21)
	for index := range loginEmails {
		loginEmails[index] = fmt.Sprintf("login-ip-%d@example.com", index)
	}
	loginByIP := attemptSeries(applicationOrigin, configuredOrigin, "/login", loginEmails, func(int) string {
		return "127.32.3.1"
	}, url.Values{"password": {"incorrect-password"}, "returnTo": {"/"}})
	totpByIP := attemptSeries(applicationOrigin, configuredOrigin, "/login/totp", make([]string, 21), func(int) string {
		return "127.32.4.1"
	}, url.Values{"returnTo": {"/"}})

	knownReset := attemptSeries(applicationOrigin, configuredOrigin, "/password-reset", loginEmailVariants[:4], func(index int) string {
		return fmt.Sprintf("127.32.5.%d", index+1)
	}, nil)
	unknownReset := attemptSeries(applicationOrigin, configuredOrigin, "/password-reset", unknownLoginVariants[:4], func(index int) string {
		return fmt.Sprintf("127.32.6.%d", index+1)
	}, nil)
	resetEmails := make([]string, 11)
	for index := range resetEmails {
		resetEmails[index] = fmt.Sprintf("reset-ip-%d@example.com", index)
	}
	resetByIP := attemptSeries(applicationOrigin, configuredOrigin, "/password-reset", resetEmails, func(int) string {
		return "127.32.7.1"
	}, nil)

	blockedAttempts := []attempt{
		knownLogin[len(knownLogin)-1],
		unknownLogin[len(unknownLogin)-1],
		loginByIP[len(loginByIP)-1],
		totpByIP[len(totpByIP)-1],
		knownReset[len(knownReset)-1],
		unknownReset[len(unknownReset)-1],
		resetByIP[len(resetByIP)-1],
	}

	writeResult(result{
		KnownLoginStatuses:            statuses(knownLogin),
		UnknownLoginStatuses:          statuses(unknownLogin),
		LoginIPStatuses:               statuses(loginByIP),
		TOTPIPStatuses:                statuses(totpByIP),
		KnownResetStatuses:            statuses(knownReset),
		UnknownResetStatuses:          statuses(unknownReset),
		ResetIPStatuses:               statuses(resetByIP),
		LoginLimitBodiesMatch:         knownLogin[len(knownLogin)-1].Body == unknownLogin[len(unknownLogin)-1].Body,
		ResetLimitBodiesMatch:         knownReset[len(knownReset)-1].Body == unknownReset[len(unknownReset)-1].Body,
		ResetNeutralBodiesMatch:       strings.Contains(knownReset[0].Body, neutralResetMessage) && strings.Contains(unknownReset[0].Body, neutralResetMessage),
		BlockedAttemptsHaveRetryAfter: allRetryable(blockedAttempts),
	})
}

func attemptSeries(applicationOrigin, configuredOrigin, path string, emails []string, sourceAddress func(int) string, extraValues url.Values) []attempt {
	attempts := make([]attempt, 0, len(emails))
	for index, email := range emails {
		values := cloneValues(extraValues)
		values.Set("email", email)
		currentAttempt, err := postForm(applicationOrigin+path, configuredOrigin, sourceAddress(index), values)
		if err != nil {
			log.Fatal(err)
		}
		attempts = append(attempts, currentAttempt)
	}
	return attempts
}

func postForm(target, origin, sourceAddress string, values url.Values) (attempt, error) {
	parsedAddress := net.ParseIP(sourceAddress)
	if parsedAddress == nil {
		return attempt{}, fmt.Errorf("parse source address %q", sourceAddress)
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: parsedAddress}}
	transport := &http.Transport{DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, strings.NewReader(values.Encode()))
	if err != nil {
		return attempt{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	response, err := client.Do(request)
	if err != nil {
		return attempt{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return attempt{}, err
	}
	return attempt{StatusCode: response.StatusCode, Body: string(body), RetryAfter: response.Header.Get("Retry-After")}, nil
}

func applicationOrigins() (string, string, error) {
	configuredOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	parsedOrigin, err := url.Parse(configuredOrigin)
	if err != nil {
		return "", "", fmt.Errorf("parse application origin: %w", err)
	}
	if parsedOrigin.Scheme == "" || parsedOrigin.Port() == "" {
		return "", "", errors.New("APP_ORIGIN must include a scheme and port")
	}
	localOrigin := parsedOrigin.Scheme + "://" + net.JoinHostPort("127.0.0.1", parsedOrigin.Port())
	return localOrigin, configuredOrigin, nil
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values)+1)
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func statuses(attempts []attempt) []int {
	output := make([]int, len(attempts))
	for index, currentAttempt := range attempts {
		output[index] = currentAttempt.StatusCode
	}
	return output
}

func allRetryable(attempts []attempt) bool {
	for _, currentAttempt := range attempts {
		if currentAttempt.RetryAfter == "" || currentAttempt.RetryAfter == "0" {
			return false
		}
	}
	return true
}

func writeResult(output result) {
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}
