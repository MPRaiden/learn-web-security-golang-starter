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
	"strconv"
	"strings"
	"time"
)

type result struct {
	EndpointAllowanceEnforced bool `json:"endpointAllowanceEnforced"`
	PublicCORSRetained        bool `json:"publicCORSRetained"`
	NormalProductsRetained    bool `json:"normalProductsRetained"`
	GlobalAllowanceRetained   bool `json:"globalAllowanceRetained"`
}

func main() {
	applicationOrigin, configuredOrigin, err := applicationOrigins()
	if err != nil {
		log.Fatal(err)
	}
	client, err := clientFrom("127.31.0.1")
	if err != nil {
		log.Fatal(err)
	}
	defer client.CloseIdleConnections()

	statuses := make([]int, 0, 31)
	var firstBody string
	var firstCORS string
	var blockedCORS string
	var blockedLimit string
	var blockedRemaining string
	var blockedRetryAfter int
	for index := range 31 {
		response, body, requestErr := request(client, applicationOrigin+"/api/products", configuredOrigin)
		if requestErr != nil {
			log.Fatal(requestErr)
		}
		statuses = append(statuses, response.StatusCode)
		if index == 0 {
			firstBody = body
			firstCORS = response.Header.Get("Access-Control-Allow-Origin")
		}
		if index == 30 {
			blockedCORS = response.Header.Get("Access-Control-Allow-Origin")
			blockedLimit = response.Header.Get("RateLimit-Limit")
			blockedRemaining = response.Header.Get("RateLimit-Remaining")
			blockedRetryAfter, _ = strconv.Atoi(response.Header.Get("Retry-After"))
		}
	}
	globalResponse, _, err := request(client, applicationOrigin+"/", "")
	if err != nil {
		log.Fatal(err)
	}

	writeResult(result{
		EndpointAllowanceEnforced: allStatus(statuses[:30], http.StatusOK) &&
			statuses[30] == http.StatusTooManyRequests && blockedLimit == "30" &&
			blockedRemaining == "0" && blockedRetryAfter > 0,
		PublicCORSRetained:     firstCORS == "*" && blockedCORS == "*",
		NormalProductsRetained: strings.Contains(firstBody, "Rate Limit Raccoon"),
		GlobalAllowanceRetained: globalResponse.StatusCode == http.StatusOK &&
			globalResponse.Header.Get("RateLimit-Limit") == "100",
	})
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

func request(client *http.Client, target, origin string) (*http.Response, string, error) {
	httpRequest, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	if origin != "" {
		httpRequest.Header.Set("Origin", origin)
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	if err != nil {
		return nil, "", err
	}
	return response, string(body), nil
}

func allStatus(statuses []int, expected int) bool {
	for _, status := range statuses {
		if status != expected {
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
