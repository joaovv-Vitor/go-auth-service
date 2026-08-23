package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	authclock "github.com/joaovv-Vitor/go-auth-service/internal/clock"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse detected")
)

type RefreshToken struct {
	ID        uuid.UUID
	FamilyID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
}

func NewRefreshToken(ttl time.Duration) (string, RefreshToken, error) {
	return NewRefreshTokenWithClock(ttl, authclock.System{})
}

func NewRefreshTokenWithClock(ttl time.Duration, clock authclock.Clock) (string, RefreshToken, error) {
	if ttl <= 0 {
		return "", RefreshToken{}, fmt.Errorf("refresh token TTL must be greater than zero")
	}
	if clock == nil {
		clock = authclock.System{}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", RefreshToken{}, fmt.Errorf("generate refresh token: %w", err)
	}

	return newRefreshToken(uuid.New(), secret, uuid.New(), clock.Now().Add(ttl))
}

func newRefreshToken(familyID uuid.UUID, secret []byte, id uuid.UUID, expiresAt time.Time) (string, RefreshToken, error) {
	return id.String() + "." + base64.RawURLEncoding.EncodeToString(secret), RefreshToken{
		ID:        id,
		FamilyID:  familyID,
		TokenHash: hashRefreshSecret(secret),
		ExpiresAt: expiresAt,
	}, nil
}

func ParseRefreshToken(value string) (uuid.UUID, []byte, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return uuid.Nil, nil, ErrInvalidRefreshToken
	}
	id, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, nil, ErrInvalidRefreshToken
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != 32 {
		return uuid.Nil, nil, ErrInvalidRefreshToken
	}
	return id, secret, nil
}

func hashRefreshSecret(secret []byte) []byte {
	digest := sha256.Sum256(secret)
	return digest[:]
}
