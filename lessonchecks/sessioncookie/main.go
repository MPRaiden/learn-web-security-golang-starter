package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database"
)

type result struct {
	LoginSucceeded                 bool `json:"loginSucceeded"`
	ExpirationPresent              bool `json:"expirationPresent"`
	ExpirationMatchesStoredSession bool `json:"expirationMatchesStoredSession"`
}

func main() {
	ctx := context.Background()
	output := result{}
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.PostForm(os.Getenv("APP_ORIGIN")+"/login", url.Values{
		"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/account"},
	})
	if err == nil {
		defer response.Body.Close()
		output.LoginSucceeded = response.StatusCode == http.StatusFound
		for _, cookie := range response.Cookies() {
			if cookie.Name != "session_id" {
				continue
			}
			output.ExpirationPresent = !cookie.Expires.IsZero()
			digest := sha256.Sum256([]byte(cookie.Value))
			databaseHandle, openErr := database.Open(ctx, os.Getenv("DATABASE_URL"))
			if openErr != nil {
				break
			}
			var storedExpiration string
			queryErr := databaseHandle.QueryRowContext(ctx, "SELECT expires_at FROM sessions WHERE token_hash = ?", hex.EncodeToString(digest[:])).Scan(&storedExpiration)
			databaseHandle.Close()
			storedTime, parseErr := time.Parse(time.RFC3339, storedExpiration)
			output.ExpirationMatchesStoredSession = queryErr == nil && parseErr == nil && cookie.Expires.Equal(storedTime.Truncate(time.Second))
			break
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
