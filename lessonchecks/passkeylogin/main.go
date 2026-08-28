package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	credentialID     = "5kcO4l1a45q4ekBss8CXgyyIcYiofd0Sm4tIo9oZqZ0"
	privateKeyBase64 = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfZz8HHXgNEigLYw+NSxsZ15rlOWCsL62wKoMBtOYusmhRANCAAR3iqSaGS3AlikcaUNgzM4y2IXu9/ETjC3lOwASEs3SSW2Fb74iCs/8xqjomTmEPvR1n41oFnU5Uu4g5qwdYTsx"
)

type result struct {
	VerifiedAssertionAccepted bool `json:"verifiedAssertionAccepted"`
	InvalidSignatureRejected  bool `json:"invalidSignatureRejected"`
	UserVerificationRequired  bool `json:"userVerificationRequired"`
}

type challengeResponse struct {
	ChallengeID string `json:"challengeId"`
	PublicKey   struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func main() {
	appOrigin := os.Getenv("APP_ORIGIN")
	parsedOrigin, err := url.Parse(appOrigin)
	if err != nil || parsedOrigin.Hostname() == "" {
		writeResult(result{})
		return
	}
	privateKey, err := parsePrivateKey()
	if err != nil {
		writeResult(result{})
		return
	}
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	validStatus, validHeaders := attemptLogin(client, privateKey, appOrigin, parsedOrigin.Hostname(), true, false)
	invalidStatus, _ := attemptLogin(client, privateKey, appOrigin, parsedOrigin.Hostname(), true, true)
	noVerificationStatus, _ := attemptLogin(client, privateKey, appOrigin, parsedOrigin.Hostname(), false, false)
	writeResult(result{
		VerifiedAssertionAccepted: validStatus == http.StatusFound && strings.Contains(validHeaders.Get("Set-Cookie"), "session_id="),
		InvalidSignatureRejected:  invalidStatus == http.StatusUnauthorized,
		UserVerificationRequired:  noVerificationStatus == http.StatusUnauthorized,
	})
}

func attemptLogin(client *http.Client, privateKey *ecdsa.PrivateKey, appOrigin, fallbackRPID string, userVerified, corruptSignature bool) (int, http.Header) {
	challenge, err := beginLogin(client, appOrigin)
	if err != nil {
		return 0, nil
	}
	rpID := challenge.PublicKey.RPID
	if rpID == "" {
		rpID = fallbackRPID
	}
	authenticatorData := make([]byte, 37)
	rpIDHash := sha256.Sum256([]byte(rpID))
	copy(authenticatorData, rpIDHash[:])
	if userVerified {
		authenticatorData[32] = 0x05
	} else {
		authenticatorData[32] = 0x01
	}
	binary.BigEndian.PutUint32(authenticatorData[33:], 0)

	encodedClientData, err := json.Marshal(clientData{
		Type: "webauthn.get", Challenge: challenge.PublicKey.Challenge, Origin: appOrigin, CrossOrigin: false,
	})
	if err != nil {
		return 0, nil
	}
	clientDataHash := sha256.Sum256(encodedClientData)
	signedBytes := append(append([]byte{}, authenticatorData...), clientDataHash[:]...)
	signedDigest := sha256.Sum256(signedBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, signedDigest[:])
	if err != nil {
		return 0, nil
	}
	if corruptSignature {
		signature[len(signature)-1] ^= 0x01
	}

	payload := map[string]any{
		"challengeId": challenge.ChallengeID,
		"returnTo":    "/account",
		"id":          credentialID,
		"rawId":       credentialID,
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(encodedClientData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        nil,
		},
		"type":                   "public-key",
		"clientExtensionResults": map[string]any{},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil
	}
	request, err := http.NewRequest(http.MethodPost, appOrigin+"/auth/passkey", bytes.NewReader(body))
	if err != nil {
		return 0, nil
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode, response.Header
}

func beginLogin(client *http.Client, appOrigin string) (challengeResponse, error) {
	response, err := client.Post(appOrigin+"/auth/passkey/begin", "application/json", nil)
	if err != nil {
		return challengeResponse{}, err
	}
	defer response.Body.Close()
	var challenge challengeResponse
	if response.StatusCode != http.StatusOK {
		return challenge, io.ErrUnexpectedEOF
	}
	if err := json.NewDecoder(response.Body).Decode(&challenge); err != nil {
		return challengeResponse{}, err
	}
	return challenge, nil
}

func parsePrivateKey() (*ecdsa.PrivateKey, error) {
	encodedKey, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(encodedKey)
	if err != nil {
		return nil, err
	}
	return parsedKey.(*ecdsa.PrivateKey), nil
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
