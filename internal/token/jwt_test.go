package token

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

func TestSignerIssuesRS256TokenAndJWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", time.Minute)
	tokenString, err := signer.Issue(user.User{ID: uuid.New(), Email: "joao@example.com", Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("auth-service"))
	if err != nil || !parsed.Valid {
		t.Fatalf("parse token: %v", err)
	}
	if claims.Email != "joao@example.com" || claims.Issuer != "auth-service" || claims.Subject == "" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if signer.PublicJWK().Kid != signer.KeyID() || signer.PublicJWK().Alg != "RS256" {
		t.Fatalf("unexpected JWK: %+v", signer.PublicJWK())
	}
	validated, err := signer.Validate(tokenString)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if validated.Subject != claims.Subject || validated.Email != claims.Email {
		t.Fatalf("unexpected validated claims: %+v", validated)
	}
}
