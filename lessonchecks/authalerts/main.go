package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

const applicationOrigin = "http://localhost:3030"

type checkResult struct {
	FailedLoginAlertAtThreshold   bool `json:"failedLoginAlertAtThreshold"`
	PasswordResetAlertAtThreshold bool `json:"passwordResetAlertAtThreshold"`
	SuccessfulLoginIgnored        bool `json:"successfulLoginIgnored"`
	FailedTOTPCounted             bool `json:"failedTotpCounted"`
	KnownResetCounted             bool `json:"knownResetCounted"`
	LoginAlertValid               bool `json:"loginAlert"`
	ResetAlertValid               bool `json:"resetAlert"`
}

type logEntry map[string]any

type responseObservation struct {
	StatusCode int
	RequestID  string
	Cookies    []*http.Cookie
}

func main() {
	result, err := checkAuthenticationAlerts(context.Background(), applicationOrigin)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		log.Fatal(err)
	}
}

func checkAuthenticationAlerts(ctx context.Context, origin string) (checkResult, error) {
	logPath := filepath.Join("data", "bearly-secure.log")
	logOffset, err := logSize(logPath)
	if err != nil {
		return checkResult{}, err
	}
	httpClient := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	failedLogins := make([]responseObservation, 0, 2)
	for attempt := range 2 {
		observation, err := postForm(ctx, httpClient, origin+"/login", url.Values{
			"email":    {fmt.Sprintf("failed-login-%d@example.com", attempt)},
			"password": {"incorrect-password"},
		}, nil)
		if err != nil {
			return checkResult{}, err
		}
		failedLogins = append(failedLogins, observation)
	}
	successfulLogin, err := postForm(ctx, httpClient, origin+"/login", url.Values{
		"email":    {"mabel@example.com"},
		"password": {"password123"},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	totpPasswordStep, err := postForm(ctx, httpClient, origin+"/login", url.Values{
		"email":    {"wendy@example.com"},
		"password": {"password123"},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}
	challengeCookie := namedCookie(totpPasswordStep.Cookies, "totp_login_challenge")
	if challengeCookie == nil {
		return checkResult{}, fmt.Errorf("TOTP password step did not set a challenge cookie")
	}
	entriesBeforeThreshold, err := appendedEntries(logPath, logOffset)
	if err != nil {
		return checkResult{}, err
	}
	failedTOTP, err := postForm(ctx, httpClient, origin+"/login/totp", url.Values{
		"mfaCode": {"not-a-code"},
	}, []*http.Cookie{challengeCookie})
	if err != nil {
		return checkResult{}, err
	}

	unknownResets := make([]responseObservation, 0, 2)
	for attempt := range 2 {
		observation, err := postForm(ctx, httpClient, origin+"/password-reset", url.Values{
			"email": {fmt.Sprintf("password-reset-%d@example.com", attempt)},
		}, nil)
		if err != nil {
			return checkResult{}, err
		}
		unknownResets = append(unknownResets, observation)
	}
	knownReset, err := postForm(ctx, httpClient, origin+"/password-reset", url.Values{
		"email": {"mabel@example.com"},
	}, nil)
	if err != nil {
		return checkResult{}, err
	}

	entries, err := appendedEntries(logPath, logOffset)
	if err != nil {
		return checkResult{}, err
	}
	loginAlert := findAlert(entries, "failed_logins")
	resetAlert := findAlert(entries, "password_reset_requests")
	return checkResult{
		FailedLoginAlertAtThreshold:   loginAlert != nil,
		PasswordResetAlertAtThreshold: resetAlert != nil,
		SuccessfulLoginIgnored:        !containsAlert(entriesBeforeThreshold, "failed_logins"),
		FailedTOTPCounted:             allStatus(failedLogins, http.StatusUnauthorized) && successfulLogin.StatusCode == http.StatusFound && totpPasswordStep.StatusCode == http.StatusFound && failedTOTP.StatusCode == http.StatusUnauthorized && loginAlert != nil,
		KnownResetCounted:             allStatus(unknownResets, http.StatusOK) && knownReset.StatusCode == http.StatusOK && resetAlert != nil,
		LoginAlertValid:               validAlert(loginAlert, "failed_logins", 3, 5*60, failedTOTP.RequestID),
		ResetAlertValid:               validAlert(resetAlert, "password_reset_requests", 3, 10*60, knownReset.RequestID),
	}, nil
}

func postForm(ctx context.Context, httpClient *http.Client, endpoint string, form url.Values, cookies []*http.Cookie) (responseObservation, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return responseObservation{}, fmt.Errorf("create request for %s: %w", endpoint, err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return responseObservation{}, fmt.Errorf("post form to %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return responseObservation{}, fmt.Errorf("read response from %s: %w", endpoint, err)
	}
	return responseObservation{
		StatusCode: response.StatusCode,
		RequestID:  response.Header.Get("X-Request-ID"),
		Cookies:    response.Cookies(),
	}, nil
}

func namedCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func logSize(logPath string) (int64, error) {
	info, err := os.Stat(logPath)
	if err != nil {
		return 0, fmt.Errorf("stat application log: %w", err)
	}
	return info.Size(), nil
}

func appendedEntries(logPath string, offset int64) ([]logEntry, error) {
	logFile, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("open application log: %w", err)
	}
	defer logFile.Close()
	if _, err := logFile.Seek(offset, 0); err != nil {
		return nil, fmt.Errorf("seek application log: %w", err)
	}

	entries := make([]logEntry, 0)
	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		var entry logEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, fmt.Errorf("parse application log: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read application log: %w", err)
	}
	return entries, nil
}

func findAlert(entries []logEntry, signal string) logEntry {
	for _, entry := range entries {
		if entry["event"] == "security_alert" && entry["signal"] == signal {
			return entry
		}
	}
	return nil
}

func containsAlert(entries []logEntry, signal string) bool {
	return findAlert(entries, signal) != nil
}

func validAlert(entry logEntry, signal string, threshold, windowSeconds int, requestID string) bool {
	if entry == nil || entry["signal"] != signal || entry["outcome"] != "threshold_crossed" ||
		entry["severity"] != "warning" || entry["threshold"] != float64(threshold) ||
		entry["windowSeconds"] != float64(windowSeconds) || entry["requestId"] != requestID ||
		entry["userId"] == nil {
		return false
	}
	if timestamp, ok := entry["timestamp"].(string); !ok || timestamp == "" {
		return false
	}
	if sourceIP, ok := entry["sourceIp"].(string); !ok || sourceIP == "" {
		return false
	}
	return true
}

func allStatus(observations []responseObservation, expectedStatus int) bool {
	for _, observation := range observations {
		if observation.StatusCode != expectedStatus {
			return false
		}
	}
	return true
}
