package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database"
)

const seededWarehouseKey = "bs_whsec_8f2d1b7a4c6e9d0f3a5b"

type result struct {
	SeededKeyStoredAsHash bool `json:"seededKeyStoredAsHash"`
	MissingKeyRejected    bool `json:"missingKeyRejected"`
	InvalidKeyRejected    bool `json:"invalidKeyRejected"`
	WrongScopeForbidden   bool `json:"wrongScopeForbidden"`
	RevokedKeyRejected    bool `json:"revokedKeyRejected"`
	WarehouseResponseSafe bool `json:"warehouseResponseSafe"`
}

func main() {
	ctx := context.Background()
	databaseHandle, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result{})
		return
	}
	defer databaseHandle.Close()
	output := result{}
	seededDigest := sha256.Sum256([]byte(seededWarehouseKey))
	var storedHash string
	if err := databaseHandle.QueryRowContext(ctx, "SELECT key_hash FROM api_keys WHERE name = ?", "Warehouse Fulfillment Integration").Scan(&storedHash); err == nil {
		output.SeededKeyStoredAsHash = storedHash == hex.EncodeToString(seededDigest[:]) && storedHash != seededWarehouseKey
	}

	wrongScopeKey := "bs_catalog_scope_check"
	revokedKey := "bs_revoked_warehouse_check"
	insertKey(ctx, databaseHandle, "Catalog Check", wrongScopeKey, "catalog:read", nil)
	revokedAt := time.Now().UTC().Format(time.RFC3339)
	insertKey(ctx, databaseHandle, "Revoked Warehouse Check", revokedKey, "orders:read", &revokedAt)

	endpoint := os.Getenv("APP_ORIGIN") + "/api/integrations/warehouse/orders"
	missingStatus, _ := request(endpoint, "")
	invalidStatus, _ := request(endpoint, "not-a-real-key")
	wrongScopeStatus, _ := request(endpoint, wrongScopeKey)
	revokedStatus, _ := request(endpoint, revokedKey)
	validStatus, validBody := request(endpoint, seededWarehouseKey)
	output.MissingKeyRejected = missingStatus == http.StatusUnauthorized
	output.InvalidKeyRejected = invalidStatus == http.StatusUnauthorized
	output.WrongScopeForbidden = wrongScopeStatus == http.StatusForbidden
	output.RevokedKeyRejected = revokedStatus == http.StatusUnauthorized
	var response struct {
		Integration string `json:"integration"`
		Orders      []struct {
			ID int64 `json:"id"`
		} `json:"orders"`
	}
	decodeErr := json.Unmarshal(validBody, &response)
	output.WarehouseResponseSafe = validStatus == http.StatusOK && decodeErr == nil && response.Integration == "Warehouse Fulfillment Integration" && len(response.Orders) > 0 && !strings.Contains(string(validBody), "admin_notes")
	_ = json.NewEncoder(os.Stdout).Encode(output)
}

func insertKey(ctx context.Context, databaseHandle *sql.DB, name, rawKey, scope string, revokedAt *string) {
	digest := sha256.Sum256([]byte(rawKey))
	_, _ = databaseHandle.ExecContext(ctx, "INSERT INTO api_keys (name, key_hash, scope, revoked_at) VALUES (?, ?, ?, ?)", name, hex.EncodeToString(digest[:]), scope, revokedAt)
}

func request(endpoint, apiKey string) (int, []byte) {
	request, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	if apiKey != "" {
		request.Header.Set("X-API-Key", apiKey)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, body
}
