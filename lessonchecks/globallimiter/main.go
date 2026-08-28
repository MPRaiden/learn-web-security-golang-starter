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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const fixedWindowProbe = `package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLessonFixedWindowRateLimiter(t *testing.T) {
	now := time.Unix(1_000, 0)
	limiter := fixedWindowRateLimiter(rateLimitOptions{
		window:  time.Minute,
		maximum: 2,
		now:     func() time.Time { return now },
	})
	handler := limiter(http.HandlerFunc(func(responseWriter http.ResponseWriter, _ *http.Request) {
		responseWriter.WriteHeader(http.StatusNoContent)
	}))

	request := func(remoteAddress string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		httpRequest := httptest.NewRequest(http.MethodGet, "/work", nil)
		httpRequest.RemoteAddr = remoteAddress
		handler.ServeHTTP(recorder, httpRequest)
		return recorder
	}

	first := request("192.0.2.10:1000")
	second := request("192.0.2.10:1001")
	otherClient := request("192.0.2.11:1000")
	blocked := request("192.0.2.10:1002")
	now = now.Add(time.Minute)
	recovered := request("192.0.2.10:1003")

	if first.Code != http.StatusNoContent || first.Header().Get("RateLimit-Limit") != "2" || first.Header().Get("RateLimit-Remaining") != "1" {
		t.Fatal("first request did not receive the expected allowance")
	}
	if second.Code != http.StatusNoContent || second.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatal("second request did not consume the allowance")
	}
	if otherClient.Code != http.StatusNoContent || otherClient.Header().Get("RateLimit-Remaining") != "1" {
		t.Fatal("different client addresses did not receive separate allowances")
	}
	if blocked.Code != http.StatusTooManyRequests || blocked.Header().Get("RateLimit-Reset") != "1060" || blocked.Header().Get("Retry-After") != "60" {
		t.Fatal("excess request did not receive deterministic retry metadata")
	}
	if recovered.Code != http.StatusNoContent || recovered.Header().Get("RateLimit-Remaining") != "1" || recovered.Header().Get("RateLimit-Reset") != "1120" {
		t.Fatal("allowance did not reset in a new fixed window")
	}
}
`

type result struct {
	FixedWindowBehavior       bool `json:"fixedWindowBehavior"`
	GlobalAllowanceEnforced   bool `json:"globalAllowanceEnforced"`
	ClientIsolationMaintained bool `json:"clientIsolationMaintained"`
	HealthExcluded            bool `json:"healthExcluded"`
}

func main() {
	fixedWindowBehavior := runFixedWindowProbe()
	applicationOrigin, err := localApplicationOrigin()
	if err != nil {
		log.Fatal(err)
	}
	limitedClient, err := clientFrom("127.30.0.1")
	if err != nil {
		log.Fatal(err)
	}
	defer limitedClient.CloseIdleConnections()
	otherClient, err := clientFrom("127.30.0.2")
	if err != nil {
		log.Fatal(err)
	}
	defer otherClient.CloseIdleConnections()

	allAllowed := true
	for range 100 {
		response, requestErr := get(limitedClient, applicationOrigin+"/")
		if requestErr != nil {
			log.Fatal(requestErr)
		}
		allAllowed = allAllowed && response.StatusCode == http.StatusOK
		response.Body.Close()
	}
	blocked, err := get(limitedClient, applicationOrigin+"/")
	if err != nil {
		log.Fatal(err)
	}
	defer blocked.Body.Close()
	other, err := get(otherClient, applicationOrigin+"/")
	if err != nil {
		log.Fatal(err)
	}
	defer other.Body.Close()
	health, err := get(limitedClient, applicationOrigin+"/health")
	if err != nil {
		log.Fatal(err)
	}
	defer health.Body.Close()

	retryAfter, _ := strconv.Atoi(blocked.Header.Get("Retry-After"))
	writeResult(result{
		FixedWindowBehavior: fixedWindowBehavior,
		GlobalAllowanceEnforced: allAllowed && blocked.StatusCode == http.StatusTooManyRequests &&
			blocked.Header.Get("RateLimit-Limit") == "100" &&
			blocked.Header.Get("RateLimit-Remaining") == "0" && retryAfter > 0,
		ClientIsolationMaintained: other.StatusCode == http.StatusOK &&
			other.Header.Get("RateLimit-Limit") == "100" &&
			other.Header.Get("RateLimit-Remaining") == "99",
		HealthExcluded: health.StatusCode == http.StatusOK && health.Header.Get("RateLimit-Limit") == "",
	})
}

func runFixedWindowProbe() bool {
	probePath := filepath.Join("internal", "httpserver", "lesson_global_limiter_test.go")
	if _, err := os.Stat(probePath); err == nil {
		log.Fatalf("temporary probe path already exists: %s", probePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Fatal(err)
	}
	if err := os.WriteFile(probePath, []byte(fixedWindowProbe), 0o600); err != nil {
		log.Fatal(err)
	}
	defer os.Remove(probePath)

	command := exec.Command("go", "test", "./internal/httpserver", "-run", "^TestLessonFixedWindowRateLimiter$", "-count=1")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	err := command.Run()
	if err == nil {
		return true
	}
	if _, ok := errors.AsType[*exec.ExitError](err); ok {
		return false
	}
	log.Fatal(err)
	return false
}

func localApplicationOrigin() (string, error) {
	configuredOrigin, err := url.Parse(strings.TrimRight(os.Getenv("APP_ORIGIN"), "/"))
	if err != nil {
		return "", fmt.Errorf("parse application origin: %w", err)
	}
	if configuredOrigin.Scheme == "" || configuredOrigin.Port() == "" {
		return "", errors.New("APP_ORIGIN must include a scheme and port")
	}
	return configuredOrigin.Scheme + "://" + net.JoinHostPort("127.0.0.1", configuredOrigin.Port()), nil
}

func clientFrom(sourceAddress string) (*http.Client, error) {
	parsedAddress := net.ParseIP(sourceAddress)
	if parsedAddress == nil {
		return nil, fmt.Errorf("parse source address %q", sourceAddress)
	}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: parsedAddress}}
	transport := &http.Transport{DialContext: dialer.DialContext}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func get(client *http.Client, target string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return response, nil
}

func writeResult(output result) {
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}
