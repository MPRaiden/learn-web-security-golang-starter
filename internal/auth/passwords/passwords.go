package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxLength = 128

const (
	memoryKiB   = 19 * 1024
	iterations  = 2
	parallelism = 1
	keylen      = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password too long")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, keylen)
	passHash := argon2idHash{
		version:     argon2.Version,
		memoryKiB:   19 * 1024,
		iterations:  2,
		parallelism: 1,
		salt:        salt,
		derivedKey:  derivedKey,
	}
	encArgHash := encodeArgon2idHash(passHash)

	return encArgHash, nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}

	candidateHash := sha256.Sum256([]byte(password))
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		if subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 0 {
			return false
		}
		return true
	}

	argExpHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if argExpHash.version != argon2.Version {
		return false
	}

	candidateArgHash := argon2.IDKey([]byte(password), argExpHash.salt, argExpHash.iterations, argExpHash.memoryKiB, argExpHash.parallelism, uint32(len(argExpHash.derivedKey)))

	if subtle.ConstantTimeCompare([]byte(candidateArgHash), []byte(argExpHash.derivedKey)) == 0 {
		return false
	}
	return true
}

func NeedsRehash(encodedHash string) bool {
	_, ok := decodeLegacyHash(encodedHash)
	if ok {
		return true
	}

	argExpHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if argExpHash.version != argon2.Version || argExpHash.memoryKiB != memoryKiB || argExpHash.iterations != iterations || argExpHash.parallelism != parallelism || uint32(len(argExpHash.derivedKey)) != keylen {
		return true
	}

	return false
}
