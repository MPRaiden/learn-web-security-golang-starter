package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
)

const probeSource = `package storage

import (
	"bytes"
	"testing"
)

func TestLessonEncryptionPolicy(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("Bearly Secure encryption probe")
	first, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(first, key)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatal("AES-GCM round trip failed")
	}
	if len(first.Nonce) != 12 || len(first.AuthTag) != 16 || bytes.Equal(first.Nonce, second.Nonce) || bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("nonce, tag, or ciphertext policy failed")
	}

	tampered := EncryptedPayload{
		Nonce: append([]byte(nil), first.Nonce...),
		AuthTag: append([]byte(nil), first.AuthTag...),
		Ciphertext: append([]byte(nil), first.Ciphertext...),
	}
	tampered.Ciphertext[0] ^= 1
	if _, err := Decrypt(tampered, key); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	wrongKey := key
	wrongKey[0] ^= 1
	if _, err := Decrypt(first, wrongKey); err == nil {
		t.Fatal("wrong key was accepted")
	}
	malformedNonce := first
	malformedNonce.Nonce = malformedNonce.Nonce[:11]
	if _, err := Decrypt(malformedNonce, key); err == nil {
		t.Fatal("malformed nonce was accepted")
	}
	malformedTag := first
	malformedTag.AuthTag = malformedTag.AuthTag[:15]
	if _, err := Decrypt(malformedTag, key); err == nil {
		t.Fatal("malformed authentication tag was accepted")
	}
}
`

type result struct {
	EncryptionPolicySatisfied bool `json:"encryptionPolicySatisfied"`
}

func main() {
	storageDirectory := filepath.Join("internal", "storage")
	_, statErr := os.Stat(storageDirectory)
	directoryCreated := os.IsNotExist(statErr)
	if err := os.MkdirAll(storageDirectory, 0o755); err != nil {
		writeResult(false)
		return
	}
	if directoryCreated {
		defer os.Remove(storageDirectory)
	}
	probePath := filepath.Join(storageDirectory, "encryption_lessoncheck_test.go")
	if err := os.WriteFile(probePath, []byte(probeSource), 0o600); err != nil {
		writeResult(false)
		return
	}
	defer os.Remove(probePath)

	command := exec.Command("go", "test", "./internal/storage", "-run", "^TestLessonEncryptionPolicy$")
	command.Stdout = os.Stderr
	command.Stderr = os.Stderr
	writeResult(command.Run() == nil)
}

func writeResult(satisfied bool) {
	_ = json.NewEncoder(os.Stdout).Encode(result{EncryptionPolicySatisfied: satisfied})
}
