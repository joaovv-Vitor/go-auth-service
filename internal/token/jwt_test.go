package token

import (
	"crypto/rand"
	"crypto/rsa"
	"slices"
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
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	tokenString, err := signer.Issue(user.User{ID: uuid.New(), Email: "joao@example.com", Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("auth-service"), jwt.WithAudience("auth-api"))
	if err != nil || !parsed.Valid {
		t.Fatalf("parse token: %v", err)
	}
	if claims.Email != "joao@example.com" || claims.Issuer != "auth-service" || claims.Subject == "" || !slices.Contains(claims.Audience, "auth-api") {
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

func TestSignerRejectsExpiredToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", -time.Minute)
	tokenString, err := signer.Issue(user.User{ID: uuid.New(), Email: "joao@example.com", Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue expired token: %v", err)
	}
	if _, err := signer.Validate(tokenString); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestSignerRejectsTokenForAnotherAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	otherService := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "other-api", time.Minute)
	tokenString, err := issuer.Issue(user.User{ID: uuid.New(), Email: "joao@example.com", Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := otherService.Validate(tokenString); err == nil {
		t.Fatal("expected token for another audience to be rejected")
	}
}

func TestSignerRejectsMissingAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	now := time.Now().UTC()
	claims := Claims{
		Email: "joao@example.com",
		Roles: []string{user.RoleUser},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-service",
			Subject:   uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
	unsigned := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	unsigned.Header["kid"] = signer.KeyID()
	tokenString, err := unsigned.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token without audience: %v", err)
	}
	if _, err := signer.Validate(tokenString); err == nil {
		t.Fatal("expected token without audience to be rejected")
	}
}

func TestSignerRejectsUnexpectedIssuerAlgorithmAndKeyID(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	found := user.User{ID: uuid.New(), Email: "joao@example.com", Role: user.RoleUser}
	validToken, err := signer.Issue(found)
	if err != nil {
		t.Fatalf("issue valid token: %v", err)
	}

	wrongIssuer := NewSigner(privateKey, &privateKey.PublicKey, "other-issuer", "auth-api", time.Minute)
	if _, err := wrongIssuer.Validate(validToken); err == nil {
		t.Fatal("expected token from another issuer to be rejected")
	}

	claims := Claims{
		Email: found.Email,
		Roles: []string{found.Role},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth-service",
			Subject:   found.ID.String(),
			Audience:  jwt.ClaimStrings{"auth-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Minute)),
		},
	}
	wrongKeyID := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	wrongKeyID.Header["kid"] = "unexpected-key"
	wrongKeyIDToken, err := wrongKeyID.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign token with wrong kid: %v", err)
	}
	if _, err := signer.Validate(wrongKeyIDToken); err == nil {
		t.Fatal("expected token with another kid to be rejected")
	}

	wrongAlgorithm := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	wrongAlgorithm.Header["kid"] = signer.KeyID()
	wrongAlgorithmToken, err := wrongAlgorithm.SignedString([]byte("not-an-rsa-key"))
	if err != nil {
		t.Fatalf("sign token with wrong algorithm: %v", err)
	}
	if _, err := signer.Validate(wrongAlgorithmToken); err == nil {
		t.Fatal("expected token with another algorithm to be rejected")
	}
}
