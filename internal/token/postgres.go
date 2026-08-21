package token

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
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
