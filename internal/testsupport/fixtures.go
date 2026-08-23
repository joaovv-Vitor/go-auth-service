package testsupport

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/uuid"
)

const (
	FixtureName         = "Test User"
	FixtureEmail        = "user@example.test"
	FixturePassword     = "test-only-password"
	FixturePasswordHash = "test-only-password-hash"
	FixtureRole         = "USER"
)

type Identity struct {
	ID           uuid.UUID
	Name         string
	Email        string
	Password     string
	PasswordHash string
	Role         string
}

func NewIdentity(email string) Identity {
	if email == "" {
		email = FixtureEmail
	}
	return Identity{
		ID:           uuid.New(),
		Name:         FixtureName,
		Email:        email,
		Password:     FixturePassword,
		PasswordHash: FixturePasswordHash,
		Role:         FixtureRole,
	}
}

// RSAKey returns an ephemeral key that exists only for the duration of a test.
func RSAKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ephemeral test RSA key: %v", err)
	}
	return privateKey
}
