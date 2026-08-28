package identifiers

import (
	"crypto/rand"
	"fmt"
)

func NewUUID() (string, error) {
	identifier := [16]byte{}
	if _, err := rand.Read(identifier[:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	identifier[6] = identifier[6]&0x0f | 0x40
	identifier[8] = identifier[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		identifier[0:4],
		identifier[4:6],
		identifier[6:8],
		identifier[8:10],
		identifier[10:16],
	), nil
}
