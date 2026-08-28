package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/auth/passwordreset"
	"github.com/bootdotdev/learn-web-security/internal/database"
)

type result struct {
	TokenIsRandom            bool `json:"tokenIsRandom"`
	OnlyTokenHashStored      bool `json:"onlyTokenHashStored"`
	ExpiresInFifteenMinutes  bool `json:"expiresInFifteenMinutes"`
	ExpiredTokenRejected     bool `json:"expiredTokenRejected"`
	AtomicSingleUse          bool `json:"atomicSingleUse"`
	SiblingTokenInvalidated  bool `json:"siblingTokenInvalidated"`
	ActiveSessionsRevoked    bool `json:"activeSessionsRevoked"`
	PendingChallengesRemoved bool `json:"pendingChallengesRemoved"`
}

type resetResult struct {
	reset bool
	err   error
}

func main() {
	ctx := context.Background()
	databaseHandle, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(result{})
		return
	}
	defer databaseHandle.Close()
	store := passwordreset.NewStore(databaseHandle)
	output := result{}

	probeToken, err := store.Create(ctx, 1)
	if err == nil {
		decoded, decodeErr := hex.DecodeString(probeToken.Value)
		output.TokenIsRandom = decodeErr == nil && len(decoded) == 32
		var storedHash, expiresAt string
		if scanErr := databaseHandle.QueryRowContext(ctx, "SELECT token_hash, expires_at FROM password_reset_tokens ORDER BY id DESC LIMIT 1").Scan(&storedHash, &expiresAt); scanErr == nil {
			digest := sha256.Sum256([]byte(probeToken.Value))
			output.OnlyTokenHashStored = storedHash == hex.EncodeToString(digest[:]) && storedHash != probeToken.Value
			if expiration, parseErr := time.Parse(time.RFC3339, expiresAt); parseErr == nil {
				remaining := time.Until(expiration)
				output.ExpiresInFifteenMinutes = remaining >= 14*time.Minute && remaining <= 16*time.Minute
			}
		}
	}

	expiredToken, err := store.Create(ctx, 2)
	if err == nil {
		_, _ = databaseHandle.ExecContext(ctx, "UPDATE password_reset_tokens SET expires_at = ? WHERE id = (SELECT MAX(id) FROM password_reset_tokens)", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339))
		_, found, validateErr := store.Validate(ctx, expiredToken.Value)
		output.ExpiredTokenRejected = validateErr == nil && !found
	}

	primaryToken, primaryErr := store.Create(ctx, 4)
	siblingToken, siblingErr := store.Create(ctx, 4)
	if primaryErr == nil && siblingErr == nil {
		now := time.Now().UTC()
		_, _ = databaseHandle.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, last_authenticated_at, created_at) VALUES (?, 4, ?, ?, ?, ?)`, "password-reset-check-session", "password-reset-check-csrf", now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339))
		_, _ = databaseHandle.ExecContext(ctx, `INSERT INTO totp_login_challenges (token_hash, user_id, return_to, attempts_remaining, expires_at, created_at) VALUES (?, 4, '/account', 3, ?, ?)`, "password-reset-check-challenge", now.Add(time.Minute).Format(time.RFC3339), now.Format(time.RFC3339))

		start := make(chan struct{})
		results := make(chan resetResult, 2)
		var waitGroup sync.WaitGroup
		for range 2 {
			waitGroup.Go(func() {
				<-start
				reset, resetErr := store.ResetPassword(ctx, primaryToken.Value, "password-reset-check-hash")
				results <- resetResult{reset: reset, err: resetErr}
			})
		}
		close(start)
		waitGroup.Wait()
		close(results)
		successes := 0
		failuresWithoutError := 0
		for resetResult := range results {
			if resetResult.err == nil && resetResult.reset {
				successes++
			}
			if resetResult.err == nil && !resetResult.reset {
				failuresWithoutError++
			}
		}
		output.AtomicSingleUse = successes == 1 && failuresWithoutError == 1

		_, siblingFound, siblingValidateErr := store.Validate(ctx, siblingToken.Value)
		output.SiblingTokenInvalidated = siblingValidateErr == nil && !siblingFound
		var revokedAt *string
		output.ActiveSessionsRevoked = databaseHandle.QueryRowContext(ctx, "SELECT revoked_at FROM sessions WHERE token_hash = ?", "password-reset-check-session").Scan(&revokedAt) == nil && revokedAt != nil
		var challengeCount int
		output.PendingChallengesRemoved = databaseHandle.QueryRowContext(ctx, "SELECT COUNT(*) FROM totp_login_challenges WHERE token_hash = ?", "password-reset-check-challenge").Scan(&challengeCount) == nil && challengeCount == 0
	}

	_ = json.NewEncoder(os.Stdout).Encode(output)
}
