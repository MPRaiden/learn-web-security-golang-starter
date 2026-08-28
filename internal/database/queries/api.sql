-- name: GetActiveAPIKeyByHash :one
SELECT id, name, key_hash, scope, revoked_at, created_at
FROM api_keys
WHERE key_hash = ?
  AND revoked_at IS NULL;

-- name: ConsumeAPIKeyQuota :one
INSERT INTO api_key_usage (api_key_id, period_start, request_count)
VALUES (?, ?, 1)
ON CONFLICT (api_key_id, period_start) DO UPDATE
SET request_count = request_count + 1
WHERE request_count < 5
RETURNING request_count;

-- name: GetAPIKeyUsage :one
SELECT request_count
FROM api_key_usage
WHERE api_key_id = ? AND period_start = ?;
