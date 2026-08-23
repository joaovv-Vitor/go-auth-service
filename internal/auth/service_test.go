package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	authclock "github.com/joaovv-Vitor/go-auth-service/internal/clock"
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

type accessStub struct {
	issued user.User
	err    error
}

func (s *accessStub) Issue(found user.User) (string, error) {
	s.issued = found
	return "access-token", s.err
}

type sessionsStub struct {
	created      token.RefreshToken
	createErr    error
	rotateUserID uuid.UUID
	rotated      string
	rotateErr    error
	revoked      string
	revokeErr    error
}

func (s *sessionsStub) Create(_ context.Context, _ uuid.UUID, refresh token.RefreshToken) error {
	s.created = refresh
	return s.createErr
}

func (s *sessionsStub) Rotate(context.Context, string) (uuid.UUID, string, error) {
	return s.rotateUserID, s.rotated, s.rotateErr
}

func (s *sessionsStub) Revoke(_ context.Context, refresh string) error {
	s.revoked = refresh
	return s.revokeErr
}

func TestLoginUnknownUserStillVerifiesDummyPasswordHash(t *testing.T) {
	verifier := &verifyStub{}
	service := NewLoginService(
		loginUsersStub{err: user.ErrNotFound},
		verifier,
		&accessStub{},
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
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	verifier := &verifyStub{valid: true}
	sessions := &sessionsStub{}
	service := NewLoginServiceWithClock(
		loginUsersStub{found: user.User{ID: userID, Email: "joao@example.com", PasswordHash: "stored-phc", Role: user.RoleUser}},
		verifier,
		&accessStub{},
		sessions,
		15*time.Minute,
		7*24*time.Hour,
		authclock.Func(func() time.Time { return now }),
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
	if !sessions.created.ExpiresAt.Equal(now.Add(7 * 24 * time.Hour)) {
		t.Fatalf("expected refresh expiration %s, got %s", now.Add(7*24*time.Hour), sessions.created.ExpiresAt)
	}
	if verifier.encodedPHC != "stored-phc" {
		t.Fatalf("expected stored password hash to be verified, got %q", verifier.encodedPHC)
	}
}

func TestLoginDoesNotCreateSessionWhenAccessTokenIssuanceFails(t *testing.T) {
	sessions := &sessionsStub{}
	service := NewLoginService(
		loginUsersStub{found: user.User{ID: uuid.New(), PasswordHash: "stored-phc"}},
		&verifyStub{valid: true},
		&accessStub{err: errors.New("signing unavailable")},
		sessions,
		15*time.Minute,
		7*24*time.Hour,
	)

	_, err := service.Login(context.Background(), LoginInput{Email: "joao@example.com", Password: "candidate-password"})
	if err == nil {
		t.Fatal("expected access token issuance failure")
	}
	if sessions.created.ID != uuid.Nil {
		t.Fatal("session must not be created when access token issuance fails")
	}
}

func TestRefreshRotatesSessionAndIssuesAccessToken(t *testing.T) {
	userID := uuid.New()
	found := user.User{ID: userID, Email: "joao@example.com", Role: user.RoleUser}
	access := &accessStub{}
	sessions := &sessionsStub{rotateUserID: userID, rotated: "rotated-refresh-token"}
	service := NewLoginService(loginUsersStub{found: found}, &verifyStub{}, access, sessions, 15*time.Minute, 7*24*time.Hour)

	result, err := service.Refresh(context.Background(), "current-refresh-token")
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}
	if result.AccessToken != "access-token" || result.RefreshToken != "rotated-refresh-token" || result.ExpiresIn != 900 {
		t.Fatalf("unexpected refresh response: %+v", result)
	}
	if access.issued.ID != found.ID {
		t.Fatalf("expected access token for user %s, got %s", found.ID, access.issued.ID)
	}
}

func TestRefreshMapsRotationFailureToPublicError(t *testing.T) {
	service := NewLoginService(
		loginUsersStub{},
		&verifyStub{},
		&accessStub{},
		&sessionsStub{rotateErr: token.ErrRefreshTokenReuse},
		15*time.Minute,
		7*24*time.Hour,
	)

	_, err := service.Refresh(context.Background(), "reused-refresh-token")
	if !errors.Is(err, ErrInvalidRefresh) {
		t.Fatalf("expected public invalid refresh error, got %v", err)
	}
}

func TestLogoutRevokesPresentedSession(t *testing.T) {
	sessions := &sessionsStub{}
	service := NewLoginService(loginUsersStub{}, &verifyStub{}, &accessStub{}, sessions, 15*time.Minute, 7*24*time.Hour)

	if err := service.Logout(context.Background(), "presented-refresh-token"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if sessions.revoked != "presented-refresh-token" {
		t.Fatalf("expected presented token to be revoked, got %q", sessions.revoked)
	}

	sessions.revokeErr = errors.New("database unavailable")
	if err := service.Logout(context.Background(), "presented-refresh-token"); !errors.Is(err, ErrInvalidRefresh) {
		t.Fatalf("expected public invalid refresh error, got %v", err)
	}
}
