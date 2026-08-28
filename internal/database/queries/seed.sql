-- name: DeletePasskeyChallenges :exec
DELETE FROM passkey_challenges;

-- name: DeletePasskeyCredentials :exec
DELETE FROM passkey_credentials;

-- name: DeleteMFARecoveryAttempts :exec
DELETE FROM mfa_recovery_attempts;

-- name: DeleteTOTPBackupCodes :exec
DELETE FROM totp_backup_codes;

-- name: DeleteImportedTaxDocuments :exec
DELETE FROM imported_tax_documents;

-- name: DeleteUploadedFiles :exec
DELETE FROM uploaded_files;

-- name: DeleteAPIKeyUsage :exec
DELETE FROM api_key_usage;

-- name: DeleteAPIKeys :exec
DELETE FROM api_keys;

-- name: DeletePasswordResetTokens :exec
DELETE FROM password_reset_tokens;

-- name: DeleteReviews :exec
DELETE FROM reviews;

-- name: DeleteOrderItems :exec
DELETE FROM order_items;

-- name: DeleteOrders :exec
DELETE FROM orders;

-- name: DeleteCartItems :exec
DELETE FROM cart_items;

-- name: DeleteProducts :exec
DELETE FROM products;

-- name: DeleteTOTPLoginChallenges :exec
DELETE FROM totp_login_challenges;

-- name: DeleteSessions :exec
DELETE FROM sessions;

-- name: DeleteUsers :exec
DELETE FROM users;

-- name: InsertSeedUser :exec
INSERT INTO users (email, display_name, role, password_hash)
VALUES (?, ?, ?, ?);

-- name: SetUserTOTPSecret :exec
UPDATE users SET totp_secret = ? WHERE email = ?;

-- name: GetUserIDByEmail :one
SELECT id FROM users WHERE email = ?;

-- name: InsertSeedTOTPBackupCode :exec
INSERT INTO totp_backup_codes (user_id, code_hash)
VALUES (?, ?);

-- name: InsertSeedPasskeyCredential :exec
INSERT INTO passkey_credentials (user_id, credential_id, public_key, counter, transports)
VALUES (?, ?, ?, 0, ?);

-- name: InsertSeedProduct :exec
INSERT INTO products (
  name,
  description,
  image_path,
  price_cents,
  cost_cents,
  inventory_count,
  is_active
)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: InsertSeedOrder :exec
INSERT INTO orders (user_id, status, total_cents, admin_notes)
VALUES (?, ?, ?, ?);

-- name: InsertSeedOrderItem :exec
INSERT INTO order_items (order_id, product_id, quantity, price_cents)
VALUES (?, ?, ?, ?);

-- name: InsertSeedReview :exec
INSERT INTO reviews (user_id, product_id, rating, body)
VALUES (?, ?, ?, ?);

-- name: InsertSeedUploadedFile :exec
INSERT INTO uploaded_files (user_id, original_name, storage_path, content_type)
VALUES (?, ?, ?, ?);

-- name: InsertSeedAPIKey :exec
INSERT INTO api_keys (name, key_hash, scope)
VALUES (?, ?, ?);
