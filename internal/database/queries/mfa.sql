-- name: ListLegacyTOTPSecrets :many
SELECT
  id,
  totp_secret,
  pending_totp_secret,
  totp_secret_encrypted,
  pending_totp_secret_encrypted
FROM users
WHERE totp_secret IS NOT NULL OR pending_totp_secret IS NOT NULL;

-- name: MigrateTOTPSecrets :exec
UPDATE users
SET
  totp_secret = NULL,
  pending_totp_secret = NULL,
  totp_secret_encrypted = ?,
  pending_totp_secret_encrypted = ?,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: GetTOTPSecret :one
SELECT totp_secret_encrypted
FROM users
WHERE id = ? AND totp_secret_encrypted IS NOT NULL;

-- name: GetPendingTOTPSecret :one
SELECT pending_totp_secret_encrypted
FROM users
WHERE id = ? AND pending_totp_secret_encrypted IS NOT NULL;

-- name: SetPendingTOTPSecret :exec
UPDATE users
SET pending_totp_secret_encrypted = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ConfirmTOTPSecret :exec
UPDATE users
SET
  totp_secret_encrypted = pending_totp_secret_encrypted,
  pending_totp_secret_encrypted = NULL,
  last_totp_step = NULL,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: ConsumeTOTPStep :execresult
UPDATE users
SET last_totp_step = sqlc.arg(time_step)
WHERE id = sqlc.arg(user_id)
  AND (last_totp_step IS NULL OR last_totp_step < sqlc.arg(time_step));

-- name: ClearTOTPSecrets :exec
UPDATE users
SET
  totp_secret = NULL,
  pending_totp_secret = NULL,
  totp_secret_encrypted = NULL,
  pending_totp_secret_encrypted = NULL,
  last_totp_step = NULL,
  updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: PruneTOTPLoginChallenges :exec
DELETE FROM totp_login_challenges
WHERE attempts_remaining <= 0 OR expires_at <= ?;

-- name: CreateTOTPLoginChallenge :exec
INSERT INTO totp_login_challenges (
  token_hash,
  user_id,
  return_to,
  attempts_remaining,
  expires_at,
  created_at
)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetTOTPLoginChallenge :one
SELECT user_id, return_to, attempts_remaining, expires_at
FROM totp_login_challenges
WHERE token_hash = ?;

-- name: RecordTOTPLoginChallengeFailure :one
UPDATE totp_login_challenges
SET attempts_remaining = attempts_remaining - 1
WHERE token_hash = sqlc.arg(token_hash)
  AND attempts_remaining > 0
  AND expires_at > sqlc.arg(now)
RETURNING attempts_remaining;

-- name: DeleteTOTPLoginChallenge :exec
DELETE FROM totp_login_challenges
WHERE token_hash = ?;

-- name: DeleteTOTPLoginChallengesForUser :exec
DELETE FROM totp_login_challenges
WHERE user_id = ?;

-- name: DeleteTOTPBackupCodesForUser :exec
DELETE FROM totp_backup_codes
WHERE user_id = ?;

-- name: CreateTOTPBackupCode :exec
INSERT INTO totp_backup_codes (user_id, code_hash)
VALUES (?, ?);

-- name: ConsumeTOTPBackupCode :execresult
UPDATE totp_backup_codes
SET used_at = CURRENT_TIMESTAMP
WHERE user_id = sqlc.arg(user_id)
  AND code_hash = sqlc.arg(code_hash)
  AND used_at IS NULL;

-- name: PruneMFARecoveryAttempts :exec
DELETE FROM mfa_recovery_attempts
WHERE created_at <= ?;

-- name: CountRecentMFARecoveryFailures :one
SELECT COUNT(*)
FROM mfa_recovery_attempts
WHERE email = sqlc.arg(email)
  AND success = 0
  AND created_at > sqlc.arg(cutoff);

-- name: RecordMFARecoveryAttempt :exec
INSERT INTO mfa_recovery_attempts (email, user_id, success, created_at)
VALUES (?, ?, ?, ?);
