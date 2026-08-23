package token

import (
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authclock "github.com/joaovv-Vitor/go-auth-service/internal/clock"
	"github.com/joaovv-Vitor/go-auth-service/internal/testsupport"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

func TestSignerIssuesRS256TokenAndJWKS(t *testing.T) {
	privateKey := testsupport.RSAKey(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	signer := NewSignerWithClock(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute, authclock.Func(func() time.Time { return now }))
	tokenString, err := signer.Issue(user.User{ID: uuid.New(), Email: testsupport.FixtureEmail, Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return signer.PublicKey(), nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("auth-service"), jwt.WithAudience("auth-api"), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || !parsed.Valid {
		t.Fatalf("parse token: %v", err)
	}
	if claims.Email != testsupport.FixtureEmail || claims.Issuer != "auth-service" || claims.Subject == "" || !slices.Contains(claims.Audience, "auth-api") {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !claims.IssuedAt.Time.Equal(now) || !claims.ExpiresAt.Time.Equal(now.Add(time.Minute)) {
		t.Fatalf("expected deterministic validity window, got issued_at=%s expires_at=%s", claims.IssuedAt, claims.ExpiresAt)
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
	privateKey := testsupport.RSAKey(t)
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	signer := NewSignerWithClock(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute, authclock.Func(func() time.Time { return now }))
	tokenString, err := signer.Issue(user.User{ID: uuid.New(), Email: testsupport.FixtureEmail, Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := signer.Validate(tokenString); err != nil {
		t.Fatalf("validate token before expiration: %v", err)
	}
	now = now.Add(time.Minute)
	if _, err := signer.Validate(tokenString); err == nil {
		t.Fatal("expected token to be rejected at its expiration boundary")
	}
}

func TestSignerRejectsTokenForAnotherAudience(t *testing.T) {
	privateKey := testsupport.RSAKey(t)
	issuer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	otherService := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "other-api", time.Minute)
	tokenString, err := issuer.Issue(user.User{ID: uuid.New(), Email: testsupport.FixtureEmail, Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := otherService.Validate(tokenString); err == nil {
		t.Fatal("expected token for another audience to be rejected")
	}
}

func TestSignerRejectsMissingAudience(t *testing.T) {
	privateKey := testsupport.RSAKey(t)
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	now := time.Now().UTC()
	claims := Claims{
		Email: testsupport.FixtureEmail,
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
	privateKey := testsupport.RSAKey(t)
	signer := NewSigner(privateKey, &privateKey.PublicKey, "auth-service", "auth-api", time.Minute)
	found := user.User{ID: uuid.New(), Email: testsupport.FixtureEmail, Role: user.RoleUser}
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
