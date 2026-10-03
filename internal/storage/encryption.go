package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func encrypt(plainText []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("new cipher creation error: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("new GCM creation error: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, fmt.Errorf("new nonce creation error: %w", err)
	}

	sealed := aead.Seal(nil, nonce, plainText, nil)
	tagStart := len(sealed) - aead.Overhead()

	return EncryptedPayload{Nonce: nonce, AuthTag: sealed[tagStart:], Ciphertext: sealed[:tagStart]}, nil
}

func decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 || len(payload.AuthTag) != 16 {
		return []byte{}, fmt.Errorf("unsupported nonce or AuthTag len")
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return []byte{}, fmt.Errorf("new cipher creation error: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, fmt.Errorf("new GCM creation error: %w", err)
	}

	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)

	encrypted, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("aead open error: %w", err)
	}

	return encrypted, nil
}
