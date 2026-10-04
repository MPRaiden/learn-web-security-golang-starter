package orders

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bootdotdev/learn-web-security/internal/storage"
)

type ShippingDetails struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	City       string `json:"city"`
	Region     string `json:"region"`
	PostalCode string `json:"postalCode"`
}

type serializedShippingDetails struct {
	Name       *string `json:"name"`
	Address    *string `json:"address"`
	City       *string `json:"city"`
	Region     *string `json:"region"`
	PostalCode *string `json:"postalCode"`
}

func EncryptShippingDetails(details ShippingDetails, kr *storage.Keyring) (string, error) {
	plaintext, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("serialize shipping details: %w", err)
	}

	encDetails, err := kr.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypting details error: %w", err)
	}

	return encDetails, nil
}

func DecryptShippingDetails(serialized string, kr *storage.Keyring) (ShippingDetails, error) {
	encDetails, err := kr.Decrypt(serialized)
	if err != nil {
		return ShippingDetails{}, fmt.Errorf("decrypt details error: %w", err)
	}

	var details serializedShippingDetails
	if err := json.Unmarshal([]byte(encDetails), &details); err != nil || details.Name == nil || details.Address == nil || details.City == nil || details.Region == nil || details.PostalCode == nil {
		return ShippingDetails{}, errors.New("invalid shipping details")
	}

	return ShippingDetails{
		Name:       *details.Name,
		Address:    *details.Address,
		City:       *details.City,
		Region:     *details.Region,
		PostalCode: *details.PostalCode,
	}, nil
}
