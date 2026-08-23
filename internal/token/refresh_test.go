package token

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRefreshTokenCanBeParsedWithoutPersistingPlaintext(t *testing.T) {
	plainText, record, err := NewRefreshToken(time.Hour)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	id, secret, err := ParseRefreshToken(plainText)
	if err != nil {
		t.Fatalf("parse refresh token: %v", err)
	}
	if id != record.ID {
		t.Fatalf("expected id %s, got %s", record.ID, id)
	}
	if !bytes.Equal(hashRefreshSecret(secret), record.TokenHash) {
		t.Fatal("expected stored hash to match the presented secret")
	}
	if bytes.Contains(record.TokenHash, secret) {
		t.Fatal("refresh token secret must not be persisted")
	}
}

func TestRotatedRefreshTokenPreservesFamilyExpiration(t *testing.T) {
	familyID := uuid.New()
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour).Round(time.Microsecond)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	_, rotated, err := newRefreshToken(familyID, secret, uuid.New(), expiresAt)
	if err != nil {
		t.Fatalf("create rotated refresh token: %v", err)
	}
	if rotated.FamilyID != familyID {
		t.Fatalf("expected family %s, got %s", familyID, rotated.FamilyID)
	}
	if !rotated.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected absolute expiration %s, got %s", expiresAt, rotated.ExpiresAt)
	}
}

func TestParseRefreshTokenRejectsMalformedInput(t *testing.T) {
	if _, _, err := ParseRefreshToken("not-a-refresh-token"); err == nil {
		t.Fatal("expected malformed refresh token to be rejected")
	}
}
