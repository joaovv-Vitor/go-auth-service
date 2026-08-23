package token

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	authclock "github.com/joaovv-Vitor/go-auth-service/internal/clock"
)

type Store struct {
	db    *pgxpool.Pool
	clock authclock.Clock
}

func NewStore(db *pgxpool.Pool) *Store {
	return NewStoreWithClock(db, authclock.System{})
}

func NewStoreWithClock(db *pgxpool.Pool, clock authclock.Clock) *Store {
	if clock == nil {
		clock = authclock.System{}
	}
	return &Store{db: db, clock: clock}
}

func (s *Store) Create(ctx context.Context, userID uuid.UUID, refresh RefreshToken) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO refresh_tokens (id, family_id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, refresh.ID, refresh.FamilyID, userID, refresh.TokenHash, refresh.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (s *Store) Rotate(ctx context.Context, presented string) (uuid.UUID, string, error) {
	id, secret, err := ParseRefreshToken(presented)
	if err != nil {
		return uuid.Nil, "", err
	}

	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer tx.Rollback(ctx)

	var current RefreshToken
	var userID uuid.UUID
	var usedAt, revokedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, family_id, user_id, token_hash, expires_at, used_at, revoked_at
		FROM refresh_tokens
		WHERE id = $1
		FOR UPDATE
	`, id).Scan(&current.ID, &current.FamilyID, &userID, &current.TokenHash, &current.ExpiresAt, &usedAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", ErrInvalidRefreshToken
	}
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("load refresh token: %w", err)
	}
	if subtle.ConstantTimeCompare(current.TokenHash, hashRefreshSecret(secret)) != 1 {
		return uuid.Nil, "", ErrInvalidRefreshToken
	}
	if usedAt != nil {
		if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE family_id = $1`, current.FamilyID); err != nil {
			return uuid.Nil, "", fmt.Errorf("revoke reused refresh family: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, "", fmt.Errorf("commit reused refresh revocation: %w", err)
		}
		return uuid.Nil, "", ErrRefreshTokenReuse
	}
	if revokedAt != nil || !s.clock.Now().Before(current.ExpiresAt) {
		return uuid.Nil, "", ErrInvalidRefreshToken
	}

	nextSecret := make([]byte, 32)
	if _, err := rand.Read(nextSecret); err != nil {
		return uuid.Nil, "", fmt.Errorf("generate rotated refresh token: %w", err)
	}
	newPlaintext, next, err := newRefreshToken(current.FamilyID, nextSecret, uuid.New(), current.ExpiresAt)
	if err != nil {
		return uuid.Nil, "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (id, family_id, parent_token_id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6)`, next.ID, next.FamilyID, current.ID, userID, next.TokenHash, next.ExpiresAt); err != nil {
		return uuid.Nil, "", fmt.Errorf("persist rotated refresh token: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET used_at = CURRENT_TIMESTAMP, revoked_at = CURRENT_TIMESTAMP, replaced_by_token_id = $2 WHERE id = $1`, current.ID, next.ID); err != nil {
		return uuid.Nil, "", fmt.Errorf("mark refresh token as used: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, "", fmt.Errorf("commit refresh rotation: %w", err)
	}
	return userID, newPlaintext, nil
}

func (s *Store) Revoke(ctx context.Context, presented string) error {
	id, secret, err := ParseRefreshToken(presented)
	if err != nil {
		return err
	}
	var storedHash []byte
	var familyID uuid.UUID
	err = s.db.QueryRow(ctx, `SELECT family_id, token_hash FROM refresh_tokens WHERE id = $1`, id).Scan(&familyID, &storedHash)
	if errors.Is(err, pgx.ErrNoRows) || subtle.ConstantTimeCompare(storedHash, hashRefreshSecret(secret)) != 1 {
		return ErrInvalidRefreshToken
	}
	_, err = s.db.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE family_id = $1`, familyID)
	if err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}
