package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/password"
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
