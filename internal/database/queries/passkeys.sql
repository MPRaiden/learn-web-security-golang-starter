-- name: ListPasskeyCredentials :many
SELECT id, user_id, credential_id, public_key, counter, transports, created_at
FROM passkey_credentials
WHERE user_id = ?
ORDER BY created_at ASC;

-- name: GetPasskeyCredentialByCredentialID :one
SELECT id, user_id, credential_id, public_key, counter, transports, created_at
FROM passkey_credentials
WHERE credential_id = ?;

-- name: CreatePasskeyCredential :exec
INSERT INTO passkey_credentials (user_id, credential_id, public_key, counter, transports)
VALUES (?, ?, ?, ?, ?);

-- name: UpdatePasskeyCredentialCounter :exec
UPDATE passkey_credentials
SET counter = ?
WHERE credential_id = ?;

-- name: DeletePasskeyCredential :exec
DELETE FROM passkey_credentials
WHERE id = ? AND user_id = ?;

-- name: DeleteExpiredPasskeyChallenges :exec
DELETE FROM passkey_challenges
WHERE expires_at <= ?;

-- name: CreatePasskeyChallenge :exec
INSERT INTO passkey_challenges (id, challenge, user_id, session_data, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ConsumePasskeyChallenge :one
DELETE FROM passkey_challenges
WHERE id = ?
RETURNING id, challenge, user_id, session_data, expires_at;
