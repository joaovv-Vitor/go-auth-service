package user

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	RoleUser  = "USER"
	RoleAdmin = "ADMIN"
)

var ErrEmailAlreadyExists = errors.New("email already exists")

type User struct {
	ID           uuid.UUID
	Name         string
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Repository interface {
	Create(ctx context.Context, newUser User) (User, error)
	FindByEmail(ctx context.Context, email string) (User, error)
}

var ErrNotFound = errors.New("user not found")
