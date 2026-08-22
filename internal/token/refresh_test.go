package token

import (
	"bytes"
	"testing"
	"time"
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

func TestParseRefreshTokenRejectsMalformedInput(t *testing.T) {
	if _, _, err := ParseRefreshToken("not-a-refresh-token"); err == nil {
		t.Fatal("expected malformed refresh token to be rejected")
	}
}
