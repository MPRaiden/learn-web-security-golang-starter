-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES (?, ?, ?);

-- name: GetPasswordResetToken :one
SELECT id, user_id, token_hash, expires_at, used_at
FROM password_reset_tokens
WHERE token_hash = ?;

-- name: ConsumePasswordResetToken :one
UPDATE password_reset_tokens
SET used_at = sqlc.arg(now)
WHERE token_hash = sqlc.arg(token_hash)
  AND used_at IS NULL
  AND expires_at > sqlc.arg(now)
RETURNING user_id;

-- name: ResetUserPasswordHash :execresult
UPDATE users
SET password_hash = sqlc.arg(password_hash), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(user_id);

-- name: ConsumeRemainingPasswordResetTokens :exec
UPDATE password_reset_tokens
SET used_at = sqlc.arg(now)
WHERE user_id = sqlc.arg(user_id) AND used_at IS NULL;

-- name: RevokeUserSessions :exec
UPDATE sessions
SET revoked_at = sqlc.arg(now)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL;
