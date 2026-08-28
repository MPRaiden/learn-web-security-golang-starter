package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	"github.com/bootdotdev/learn-web-security/internal/auth/passwords"
)

type result struct {
	Argon2idBaselineUsed  bool `json:"argon2idBaselineUsed"`
	FreshSaltsUsed        bool `json:"freshSaltsUsed"`
	CorrectPasswordWorks  bool `json:"correctPasswordWorks"`
	WrongPasswordRejected bool `json:"wrongPasswordRejected"`
	LegacyHashSupported   bool `json:"legacyHashSupported"`
	MalformedHashRejected bool `json:"malformedHashRejected"`
}

func main() {
	first, firstErr := passwords.Hash("correct horse battery staple")
	second, secondErr := passwords.Hash("correct horse battery staple")
	legacyDigest := sha256.Sum256([]byte("legacy password"))
	legacyHash := hex.EncodeToString(legacyDigest[:])

	writeResult(result{
		Argon2idBaselineUsed:  firstErr == nil && strings.HasPrefix(first, "$argon2id$v=19$m=19456,t=2,p=1$"),
		FreshSaltsUsed:        firstErr == nil && secondErr == nil && first != second,
		CorrectPasswordWorks:  passwords.Verify("correct horse battery staple", first),
		WrongPasswordRejected: !passwords.Verify("incorrect password", first),
		LegacyHashSupported:   passwords.Verify("legacy password", legacyHash) && !passwords.Verify("wrong legacy password", legacyHash),
		MalformedHashRejected: !passwords.Verify("password", "$argon2id$malformed") && !passwords.Verify("password", "not-a-hash"),
	})
}

func writeResult(output result) {
	_ = json.NewEncoder(os.Stdout).Encode(output)
}
