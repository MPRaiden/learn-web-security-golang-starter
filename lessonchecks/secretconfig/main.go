package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/config"
)

const (
	applicationOrigin  = "http://localhost:3030"
	pawPalKey          = "bs_test_pawpal_lesson_key"
	downloadSigningHex = "2222222222222222222222222222222222222222222222222222222222222222"
)

type result struct {
	PawPalKeyRequired         bool `json:"pawPalKeyRequired"`
	PawPalKeyInjected         bool `json:"pawPalKeyInjected"`
	DownloadKeyRequired       bool `json:"downloadKeyRequired"`
	InvalidDownloadKeyDenied  bool `json:"invalidDownloadKeyDenied"`
	DotenvLoaded              bool `json:"dotenvLoaded"`
	ProcessEnvironmentWins    bool `json:"processEnvironmentWins"`
	ConfiguredDownloadKeyUsed bool `json:"configuredDownloadKeyUsed"`
}

func main() {
	validEnvironment := map[string]string{
		"PAWPAL_API_KEY":       pawPalKey,
		"DOWNLOAD_SIGNING_KEY": downloadSigningHex,
	}
	missingPawPalEnvironment := map[string]string{"DOWNLOAD_SIGNING_KEY": downloadSigningHex}
	_, missingPawPalError := config.Parse(missingPawPalEnvironment, ".")
	parsedConfig, parseError := config.Parse(validEnvironment, ".")

	missingDownloadEnvironment := map[string]string{"PAWPAL_API_KEY": pawPalKey}
	_, missingDownloadError := config.Parse(missingDownloadEnvironment, ".")
	invalidDownloadEnvironment := map[string]string{
		"PAWPAL_API_KEY":       pawPalKey,
		"DOWNLOAD_SIGNING_KEY": "not-a-64-character-hex-key",
	}
	_, invalidDownloadError := config.Parse(invalidDownloadEnvironment, ".")

	dotenvLoaded, processEnvironmentWins := checkDotenvPrecedence()
	configuredDownloadKeyUsed := checkSignedDownload()

	writeResult(result{
		PawPalKeyRequired:         missingPawPalError != nil,
		PawPalKeyInjected:         parseError == nil && parsedConfig.PawPalAPIKey == pawPalKey,
		DownloadKeyRequired:       missingDownloadError != nil,
		InvalidDownloadKeyDenied:  invalidDownloadError != nil,
		DotenvLoaded:              dotenvLoaded,
		ProcessEnvironmentWins:    processEnvironmentWins,
		ConfiguredDownloadKeyUsed: configuredDownloadKeyUsed,
	})
}

func checkDotenvPrecedence() (bool, bool) {
	directory, err := os.MkdirTemp("", "secret-config-")
	if err != nil {
		return false, false
	}
	defer os.RemoveAll(directory)
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("PAWPAL_API_KEY=dotenv-key\n"), 0o600); err != nil {
		return false, false
	}

	originalPawPal, hadPawPal := os.LookupEnv("PAWPAL_API_KEY")
	originalDownload, hadDownload := os.LookupEnv("DOWNLOAD_SIGNING_KEY")
	defer restoreEnvironment("PAWPAL_API_KEY", originalPawPal, hadPawPal)
	defer restoreEnvironment("DOWNLOAD_SIGNING_KEY", originalDownload, hadDownload)

	_ = os.Unsetenv("PAWPAL_API_KEY")
	_ = os.Setenv("DOWNLOAD_SIGNING_KEY", downloadSigningHex)
	loadedConfig, loadError := config.Load(directory)
	dotenvLoaded := loadError == nil && loadedConfig.PawPalAPIKey == "dotenv-key"

	_ = os.Setenv("PAWPAL_API_KEY", "process-key")
	loadedConfig, loadError = config.Load(directory)
	processEnvironmentWins := loadError == nil && loadedConfig.PawPalAPIKey == "process-key"
	return dotenvLoaded, processEnvironmentWins
}

func restoreEnvironment(name, value string, present bool) {
	if present {
		_ = os.Setenv(name, value)
		return
	}
	_ = os.Unsetenv(name)
}

func checkSignedDownload() bool {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	form := url.Values{"email": {"mabel@example.com"}, "password": {"password123"}, "returnTo": {"/"}}
	request, err := http.NewRequest(http.MethodPost, applicationOrigin+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", applicationOrigin)
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound {
		return false
	}

	downloadRequest, err := http.NewRequest(http.MethodGet, applicationOrigin+"/files/1/download", nil)
	if err != nil {
		return false
	}
	for _, cookie := range response.Cookies() {
		downloadRequest.AddCookie(cookie)
	}
	downloadResponse, err := client.Do(downloadRequest)
	if err != nil {
		return false
	}
	downloadResponse.Body.Close()
	if downloadResponse.StatusCode != http.StatusFound {
		return false
	}
	location, err := url.Parse(downloadResponse.Header.Get("Location"))
	if err != nil {
		return false
	}
	keyBytes, err := hex.DecodeString(downloadSigningHex)
	if err != nil || len(keyBytes) != 32 {
		return false
	}
	var key [32]byte
	copy(key[:], keyBytes)
	expires, err := strconv.ParseInt(location.Query().Get("expires"), 10, 64)
	if err != nil || expires <= time.Now().Unix() {
		return false
	}
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "GET\n/files/1/signed-download\n%d", expires)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expectedSignature), []byte(location.Query().Get("signature")))
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
