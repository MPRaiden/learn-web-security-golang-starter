-- name: GetUserByEmail :one
SELECT
  id,
  email,
  display_name,
  role,
  password_hash,
  CASE WHEN totp_secret IS NOT NULL OR totp_secret_encrypted IS NOT NULL THEN 1 ELSE 0 END AS has_totp,
  CASE WHEN pending_totp_secret IS NOT NULL OR pending_totp_secret_encrypted IS NOT NULL THEN 1 ELSE 0 END AS has_pending_totp,
  created_at,
  updated_at
FROM users
WHERE email = ?;

-- name: GetUserByID :one
SELECT
  id,
  email,
  display_name,
  role,
  password_hash,
  CASE WHEN totp_secret IS NOT NULL OR totp_secret_encrypted IS NOT NULL THEN 1 ELSE 0 END AS has_totp,
  CASE WHEN pending_totp_secret IS NOT NULL OR pending_totp_secret_encrypted IS NOT NULL THEN 1 ELSE 0 END AS has_pending_totp,
  created_at,
  updated_at
FROM users
WHERE id = ?;

-- name: CreateCustomer :one
INSERT INTO users (email, display_name, role, password_hash)
VALUES (?, ?, 'customer', ?)
ON CONFLICT(email) DO NOTHING
RETURNING id;

-- name: UpdateUserPasswordHash :exec
UPDATE users
SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: UpdateUserEmail :one
UPDATE OR IGNORE users
SET email = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id;

-- name: CreateSession :exec
INSERT INTO sessions (
  token_hash,
  user_id,
  csrf_token,
  expires_at,
  last_authenticated_at,
  created_at
)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetSessionByTokenHash :one
SELECT user_id, csrf_token, expires_at, revoked_at, last_authenticated_at, created_at
FROM sessions
WHERE token_hash = ?;

-- name: RevokeSession :exec
UPDATE sessions
SET revoked_at = ?
WHERE token_hash = ?;

-- name: RevokeAllActiveSessions :execrows
UPDATE sessions
SET revoked_at = CURRENT_TIMESTAMP
WHERE revoked_at IS NULL;

-- name: ListCartQuantities :many
SELECT product_id, quantity
FROM cart_items
WHERE user_id = ?;
