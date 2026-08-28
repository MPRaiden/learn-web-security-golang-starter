package uploads

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type StoredDocument struct {
	ContentType string
	StoragePath string
}

func StoreDocument(contents []byte, originalName, contentType, uploadDirectory string) (StoredDocument, error) {
	if err := os.MkdirAll(uploadDirectory, 0o755); err != nil {
		return StoredDocument{}, fmt.Errorf("create upload directory: %w", err)
	}
	storagePath := filepath.Join(uploadDirectory, originalName)
	if err := os.WriteFile(storagePath, contents, 0o644); err != nil {
		return StoredDocument{}, fmt.Errorf("write tax document: %w", err)
	}
	return StoredDocument{ContentType: contentType, StoragePath: storagePath}, nil
}

func ReadDocument(storagePath string) ([]byte, error) {
	contents, err := os.ReadFile(storagePath)
	if err != nil {
		return nil, fmt.Errorf("read tax document: %w", err)
	}
	return contents, nil
}

func RemoveDocument(storagePath string) error {
	if err := os.Remove(storagePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove tax document: %w", err)
	}
	return nil
}
