package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	db *pgxpool.Pool
}

func NewPostgresRepository(db *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{db: db}
}

func (r *PostgresRepository) Create(ctx context.Context, newUser User) (User, error) {
	if newUser.ID == uuid.Nil {
		newUser.ID = uuid.New()
	}

	err := r.db.QueryRow(ctx, `
		INSERT INTO users (id, name, email, password_hash, role)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`, newUser.ID, newUser.Name, newUser.Email, newUser.PasswordHash, newUser.Role).
		Scan(&newUser.CreatedAt, &newUser.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return User{}, ErrEmailAlreadyExists
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}

	return newUser, nil
}

func (r *PostgresRepository) FindByEmail(ctx context.Context, email string) (User, error) {
	var found User
	err := r.db.QueryRow(ctx, `
		SELECT id, name, email, password_hash, role, created_at, updated_at
		FROM users
		WHERE email = $1
	`, email).Scan(
		&found.ID,
		&found.Name,
		&found.Email,
		&found.PasswordHash,
		&found.Role,
		&found.CreatedAt,
		&found.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user by email: %w", err)
	}
	return found, nil
}

func (r *PostgresRepository) FindByID(ctx context.Context, id uuid.UUID) (User, error) {
	var found User
	err := r.db.QueryRow(ctx, `
		SELECT id, name, email, password_hash, role, created_at, updated_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&found.ID,
		&found.Name,
		&found.Email,
		&found.PasswordHash,
		&found.Role,
		&found.CreatedAt,
		&found.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("find user by id: %w", err)
	}
	return found, nil
}

var _ Repository = (*PostgresRepository)(nil)
