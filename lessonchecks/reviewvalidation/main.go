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
	"strings"
)

type results struct {
	WhitespaceRejected         bool `json:"whitespaceRejected"`
	OversizedRejected          bool `json:"oversizedRejected"`
	BoundaryAcceptedAndTrimmed bool `json:"boundaryAcceptedAndTrimmed"`
}

func main() {
	output, err := checkReviews(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		log.Fatal(err)
	}
}

func checkReviews(ctx context.Context) (results, error) {
	applicationOrigin := strings.TrimRight(os.Getenv("APP_ORIGIN"), "/")
	if applicationOrigin == "" {
		applicationOrigin = "http://localhost:3030"
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return results{}, err
	}
	httpClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	loginResponse, err := submitForm(ctx, httpClient, applicationOrigin+"/login", url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/account/reviews/1/edit"},
	})
	if err != nil {
		return results{}, err
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusFound {
		return results{}, fmt.Errorf("log in: status %d", loginResponse.StatusCode)
	}

	whitespaceStatus, err := updateReview(ctx, httpClient, applicationOrigin, "   \t\n")
	if err != nil {
		return results{}, err
	}
	oversizedStatus, err := updateReview(ctx, httpClient, applicationOrigin, strings.Repeat("a", 1001))
	if err != nil {
		return results{}, err
	}
	boundaryBody := strings.Repeat("é", 1000)
	boundaryStatus, err := updateReview(ctx, httpClient, applicationOrigin, "  "+boundaryBody+" \n")
	if err != nil {
		return results{}, err
	}
	editRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, applicationOrigin+"/account/reviews/1/edit", nil)
	if err != nil {
		return results{}, err
	}
	editResponse, err := httpClient.Do(editRequest)
	if err != nil {
		return results{}, err
	}
	defer editResponse.Body.Close()
	editPage, err := io.ReadAll(io.LimitReader(editResponse.Body, 1024*1024))
	if err != nil {
		return results{}, err
	}

	return results{
		WhitespaceRejected:         whitespaceStatus == http.StatusBadRequest,
		OversizedRejected:          oversizedStatus == http.StatusBadRequest,
		BoundaryAcceptedAndTrimmed: boundaryStatus == http.StatusFound && editResponse.StatusCode == http.StatusOK && strings.Contains(string(editPage), "\n"+boundaryBody+"</textarea>"),
	}, nil
}

func updateReview(ctx context.Context, httpClient *http.Client, applicationOrigin, body string) (int, error) {
	response, err := submitForm(ctx, httpClient, applicationOrigin+"/account/reviews/1", url.Values{
		"rating": {"5"}, "body": {body},
	})
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, nil
}

func submitForm(ctx context.Context, httpClient *http.Client, endpoint string, values url.Values) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return httpClient.Do(request)
}
