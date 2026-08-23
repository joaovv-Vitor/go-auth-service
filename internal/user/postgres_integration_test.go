package user

import (
	"context"
	"errors"
	"testing"

	"github.com/joaovv-Vitor/go-auth-service/internal/testsupport"
)

func TestPostgresRepositoryCreatesFindsAndRejectsDuplicateEmail(t *testing.T) {
	database := testsupport.OpenPostgres(t)
	repository := NewPostgresRepository(database.Pool)
	ctx := context.Background()

	created, err := repository.Create(ctx, User{
		Name:         "João",
		Email:        "joao@example.com",
		PasswordHash: "argon2id-phc",
		Role:         RoleUser,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.ID.String() == "" || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatalf("expected generated persistence fields, got %+v", created)
	}

	byEmail, err := repository.FindByEmail(ctx, created.Email)
	if err != nil {
		t.Fatalf("find user by email: %v", err)
	}
	byID, err := repository.FindByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("find user by ID: %v", err)
	}
	if byEmail.ID != created.ID || byID.Email != created.Email || byID.PasswordHash != "argon2id-phc" {
		t.Fatalf("unexpected persisted users: byEmail=%+v byID=%+v", byEmail, byID)
	}

	_, err = repository.Create(ctx, User{
		Name:         "Outro",
		Email:        created.Email,
		PasswordHash: "another-phc",
		Role:         RoleUser,
	})
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("expected duplicate email error, got %v", err)
	}
}
