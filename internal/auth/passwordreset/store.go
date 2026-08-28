package passwordreset

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

type Token struct {
	ID        int64
	UserID    int64
	ExpiresAt time.Time
	UsedAt    *string
	Value     string
}

type Store struct {
	queries *dbgen.Queries
	now     func() time.Time
}

func NewStore(database *sql.DB) *Store {
	return &Store{queries: dbgen.New(database), now: time.Now}
}

func (store *Store) Create(ctx context.Context, userID int64) (Token, error) {
	now := store.now().UTC()
	value := fmt.Sprintf("reset-%d-%d", userID, now.UnixNano())
	expiresAt := now.Add(30 * 24 * time.Hour)
	if err := store.queries.CreatePasswordResetToken(ctx, dbgen.CreatePasswordResetTokenParams{
		UserID: userID, TokenHash: value, ExpiresAt: formatTimestamp(expiresAt),
	}); err != nil {
		return Token{}, fmt.Errorf("create password reset token: %w", err)
	}
	return Token{UserID: userID, ExpiresAt: expiresAt, Value: value}, nil
}

func (store *Store) Validate(ctx context.Context, value string) (Token, bool, error) {
	row, err := store.queries.GetPasswordResetToken(ctx, value)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, fmt.Errorf("find password reset token: %w", err)
	}
	expiresAt, _ := time.Parse(time.RFC3339, row.ExpiresAt)
	return Token{ID: row.ID, UserID: row.UserID, ExpiresAt: expiresAt, UsedAt: row.UsedAt, Value: value}, true, nil
}

func (store *Store) ResetPassword(ctx context.Context, value, passwordHash string) (bool, error) {
	token, found, err := store.Validate(ctx, value)
	if err != nil || !found {
		return false, err
	}
	result, err := store.queries.ResetUserPasswordHash(ctx, dbgen.ResetUserPasswordHashParams{
		PasswordHash: passwordHash, Now: formatTimestamp(store.now().UTC()), UserID: token.UserID,
	})
	if err != nil {
		return false, fmt.Errorf("reset user password: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	return rowsAffected == 1, err
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
