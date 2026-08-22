package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/password"
	"github.com/joaovv-Vitor/go-auth-service/internal/token"
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

type LoginInput struct {
	Email    string
	Password string
}

type LoginResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type Authenticator interface {
	Login(ctx context.Context, input LoginInput) (LoginResponse, error)
	Refresh(ctx context.Context, refreshToken string) (LoginResponse, error)
	Logout(ctx context.Context, refreshToken string) error
}

var ErrInvalidCredentials = errors.New("invalid credentials")

type LoginService struct {
	users interface {
		FindByEmail(context.Context, string) (user.User, error)
		FindByID(context.Context, uuid.UUID) (user.User, error)
	}
	hasher interface {
		Verify(string, string) (bool, error)
	}
	access interface {
		Issue(user.User) (string, error)
	}
	sessions interface {
		Create(context.Context, uuid.UUID, token.RefreshToken) error
		Rotate(context.Context, string, time.Duration) (uuid.UUID, string, error)
		Revoke(context.Context, string) error
	}
	accessTTL  time.Duration
	refreshTTL time.Duration
}

var ErrInvalidRefresh = errors.New("invalid refresh token")

func NewLoginService(
	users interface {
		FindByEmail(context.Context, string) (user.User, error)
		FindByID(context.Context, uuid.UUID) (user.User, error)
	},
	hasher interface {
		Verify(string, string) (bool, error)
	},
	access interface {
		Issue(user.User) (string, error)
	},
	sessions interface {
		Create(context.Context, uuid.UUID, token.RefreshToken) error
		Rotate(context.Context, string, time.Duration) (uuid.UUID, string, error)
		Revoke(context.Context, string) error
	},
	accessTTL time.Duration,
	refreshTTL time.Duration,
) *LoginService {
	return &LoginService{users: users, hasher: hasher, access: access, sessions: sessions, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (s *LoginService) Login(ctx context.Context, input LoginInput) (LoginResponse, error) {
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if input.Email == "" || input.Password == "" || s.users == nil || s.hasher == nil || s.access == nil || s.sessions == nil {
		return LoginResponse{}, ErrInvalidCredentials
	}

	found, err := s.users.FindByEmail(ctx, input.Email)
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return LoginResponse{}, ErrInvalidCredentials
		}
		return LoginResponse{}, fmt.Errorf("find login user: %w", err)
	}
	valid, err := s.hasher.Verify(input.Password, found.PasswordHash)
	if err != nil || !valid {
		return LoginResponse{}, ErrInvalidCredentials
	}

	accessToken, err := s.access.Issue(found)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("issue access token: %w", err)
	}
	refreshPlaintext, refresh, err := token.NewRefreshToken(s.refreshTTL)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("issue refresh token: %w", err)
	}
	if err := s.sessions.Create(ctx, found.ID, refresh); err != nil {
		return LoginResponse{}, fmt.Errorf("persist refresh token: %w", err)
	}

	return LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshPlaintext,
		ExpiresIn:    int64(s.accessTTL.Seconds()),
	}, nil
}

func (s *LoginService) Refresh(ctx context.Context, refreshToken string) (LoginResponse, error) {
	if s.users == nil || s.access == nil || s.sessions == nil {
		return LoginResponse{}, ErrInvalidRefresh
	}
	userID, nextRefresh, err := s.sessions.Rotate(ctx, refreshToken, s.refreshTTL)
	if err != nil {
		return LoginResponse{}, ErrInvalidRefresh
	}
	found, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("find refresh user: %w", err)
	}
	accessToken, err := s.access.Issue(found)
	if err != nil {
		return LoginResponse{}, fmt.Errorf("issue refreshed access token: %w", err)
	}
	return LoginResponse{AccessToken: accessToken, RefreshToken: nextRefresh, ExpiresIn: int64(s.accessTTL.Seconds())}, nil
}

func (s *LoginService) Logout(ctx context.Context, refreshToken string) error {
	if s.sessions == nil {
		return ErrInvalidRefresh
	}
	if err := s.sessions.Revoke(ctx, refreshToken); err != nil {
		return ErrInvalidRefresh
	}
	return nil
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
