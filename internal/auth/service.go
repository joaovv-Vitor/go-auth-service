package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/joaovv-Vitor/go-auth-service/internal/password"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

var (
	ErrInvalidRegistration = errors.New("invalid registration")
	ErrServiceUnavailable  = errors.New("authentication service unavailable")
)

type RegisterInput struct {
	Name     string
	Email    string
	Password string
}

type Registerer interface {
	Register(ctx context.Context, input RegisterInput) (user.User, error)
}

type Service struct {
	users  user.Repository
	hasher interface {
		Hash(string) (string, error)
	}
}

func NewService(users user.Repository, hasher password.Hasher) *Service {
	return &Service{users: users, hasher: hasher}
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (user.User, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	parsedEmail, emailErr := mail.ParseAddress(input.Email)
	if input.Name == "" || len(input.Name) > 120 || emailErr != nil || parsedEmail.Address != input.Email || len(input.Email) > 320 || len(input.Password) < 12 || len(input.Password) > 128 {
		return user.User{}, ErrInvalidRegistration
	}
	if s.users == nil || s.hasher == nil {
		return user.User{}, ErrServiceUnavailable
	}

	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return user.User{}, fmt.Errorf("hash registration password: %w", err)
	}

	created, err := s.users.Create(ctx, user.User{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: passwordHash,
		Role:         user.RoleUser,
	})
	if err != nil {
		return user.User{}, err
	}
	return created, nil
}

var _ Registerer = (*Service)(nil)
