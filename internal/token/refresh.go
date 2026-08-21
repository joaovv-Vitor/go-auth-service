package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID
	FamilyID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
}

func NewRefreshToken(ttl time.Duration) (string, RefreshToken, error) {
	if ttl <= 0 {
		return "", RefreshToken{}, fmt.Errorf("refresh token TTL must be greater than zero")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", RefreshToken{}, fmt.Errorf("generate refresh token: %w", err)
	}

	id := uuid.New()
	familyID := uuid.New()
	return id.String() + "." + base64.RawURLEncoding.EncodeToString(secret), RefreshToken{
		ID:        id,
		FamilyID:  familyID,
		TokenHash: hashRefreshSecret(secret),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}, nil
}

func hashRefreshSecret(secret []byte) []byte {
	digest := sha256.Sum256(secret)
	return digest[:]
}
