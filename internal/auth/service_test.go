package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/password"
	"github.com/joaovv-Vitor/go-auth-service/internal/token"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

type repositoryStub struct {
	created user.User
}

func (r *repositoryStub) Create(_ context.Context, newUser user.User) (user.User, error) {
	r.created = newUser
	return newUser, nil
}

func (r *repositoryStub) FindByEmail(_ context.Context, email string) (user.User, error) {
	return user.User{Email: email}, nil
}

func (r *repositoryStub) FindByID(_ context.Context, id uuid.UUID) (user.User, error) {
	return user.User{ID: id, Email: "joao@example.com", Role: user.RoleUser}, nil
}

func TestRegisterNormalizesEmailAndNeverAcceptsRole(t *testing.T) {
	repository := &repositoryStub{}
	service := NewService(repository, password.DefaultHasher())

	created, err := service.Register(context.Background(), RegisterInput{
		Name:     " João ",
		Email:    " JOAO@EXAMPLE.COM ",
		Password: "a-strong-password",
	})
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	if created.Name != "João" || created.Email != "joao@example.com" || created.Role != user.RoleUser {
		t.Fatalf("unexpected user: %+v", created)
	}
	if created.PasswordHash == "a-strong-password" || created.PasswordHash == "" {
		t.Fatal("expected password to be persisted as a hash")
	}
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	service := NewService(&repositoryStub{}, password.DefaultHasher())

	_, err := service.Register(context.Background(), RegisterInput{
		Name:     "João",
		Email:    "joao@example.com",
		Password: "short",
	})
	if err != ErrInvalidRegistration {
		t.Fatalf("expected invalid registration, got %v", err)
	}
}

func TestRegisterRejectsInvalidEmail(t *testing.T) {
	service := NewService(&repositoryStub{}, password.DefaultHasher())

	_, err := service.Register(context.Background(), RegisterInput{
		Name:     "João",
		Email:    "not-an-email",
		Password: "a-strong-password",
	})
	if err != ErrInvalidRegistration {
		t.Fatalf("expected invalid registration, got %v", err)
	}
}

type loginUsersStub struct {
	found user.User
	err   error
}

func (s loginUsersStub) FindByEmail(context.Context, string) (user.User, error) {
	return s.found, s.err
}

func (s loginUsersStub) FindByID(context.Context, uuid.UUID) (user.User, error) {
	return s.found, s.err
}

type verifyStub struct {
	valid      bool
	calls      int
	encodedPHC string
}

func (s *verifyStub) Verify(_ string, encodedPHC string) (bool, error) {
	s.calls++
	s.encodedPHC = encodedPHC
	return s.valid, nil
}

type accessStub struct{}

func (accessStub) Issue(user.User) (string, error) { return "access-token", nil }

type sessionsStub struct {
	created token.RefreshToken
}

func (s *sessionsStub) Create(_ context.Context, _ uuid.UUID, refresh token.RefreshToken) error {
	s.created = refresh
	return nil
}

func (s *sessionsStub) Rotate(context.Context, string) (uuid.UUID, string, error) {
	return uuid.Nil, "", errors.New("not implemented")
}

func (s *sessionsStub) Revoke(context.Context, string) error { return nil }

func TestLoginUnknownUserStillVerifiesDummyPasswordHash(t *testing.T) {
	verifier := &verifyStub{}
	service := NewLoginService(
		loginUsersStub{err: user.ErrNotFound},
		verifier,
		accessStub{},
		&sessionsStub{},
		15*time.Minute,
		7*24*time.Hour,
	)

	_, err := service.Login(context.Background(), LoginInput{Email: "missing@example.com", Password: "candidate-password"})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if verifier.calls != 1 || verifier.encodedPHC != dummyPasswordHash {
		t.Fatalf("expected one dummy password verification, got calls=%d hash=%q", verifier.calls, verifier.encodedPHC)
	}
}

func TestLoginPersistsHashedRefreshTokenBeforeReturning(t *testing.T) {
	userID := uuid.New()
	verifier := &verifyStub{valid: true}
	sessions := &sessionsStub{}
	service := NewLoginService(
		loginUsersStub{found: user.User{ID: userID, Email: "joao@example.com", PasswordHash: "stored-phc", Role: user.RoleUser}},
		verifier,
		accessStub{},
		sessions,
		15*time.Minute,
		7*24*time.Hour,
	)

	result, err := service.Login(context.Background(), LoginInput{Email: " JOAO@EXAMPLE.COM ", Password: "candidate-password"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.ExpiresIn != 900 {
		t.Fatalf("unexpected login response: %+v", result)
	}
	if len(sessions.created.TokenHash) == 0 || sessions.created.ID == uuid.Nil || sessions.created.FamilyID == uuid.Nil {
		t.Fatalf("expected persisted refresh token metadata, got %+v", sessions.created)
	}
	if verifier.encodedPHC != "stored-phc" {
		t.Fatalf("expected stored password hash to be verified, got %q", verifier.encodedPHC)
	}
}
