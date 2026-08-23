package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joaovv-Vitor/go-auth-service/internal/auth"
	"github.com/joaovv-Vitor/go-auth-service/internal/config"
	"github.com/joaovv-Vitor/go-auth-service/internal/password"
	"github.com/joaovv-Vitor/go-auth-service/internal/testsupport"
	"github.com/joaovv-Vitor/go-auth-service/internal/token"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

func TestCompleteV1AuthenticationFlow(t *testing.T) {
	database := testsupport.OpenPostgres(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer := token.NewSigner(privateKey, &privateKey.PublicKey, "integration-auth-service", 15*time.Minute)
	users := user.NewPostgresRepository(database.Pool)
	sessions := token.NewStore(database.Pool)
	handler := NewHandler(config.Config{AppEnv: "test"}, Dependencies{
		Database:      database.Pool,
		Registerer:    auth.NewService(users, password.DefaultHasher()),
		Authenticator: auth.NewLoginService(users, password.DefaultHasher(), signer, sessions, 15*time.Minute, 7*24*time.Hour),
		JWKProvider:   signer,
		TokenVerifier: signer,
	})

	register := performRequest(t, handler, http.MethodPost, "/api/v1/auth/register",
		`{"name":"João","email":"joao@example.com","password":"a-strong-password"}`,
		map[string]string{"Content-Type": "application/json"})
	assertStatus(t, register.Code, http.StatusCreated, register.Body.String())

	login := performRequest(t, handler, http.MethodPost, "/api/v1/auth/login",
		`{"email":"joao@example.com","password":"a-strong-password"}`,
		map[string]string{"Content-Type": "application/json"})
	assertStatus(t, login.Code, http.StatusOK, login.Body.String())
	loginTokens := decodeTokenPair(t, login.Body.Bytes())

	currentUser := performRequest(t, handler, http.MethodGet, "/api/v1/users/me", "",
		map[string]string{"Authorization": "Bearer " + loginTokens.AccessToken})
	assertStatus(t, currentUser.Code, http.StatusOK, currentUser.Body.String())

	validateAccessTokenFromHTTPJWKS(t, handler, loginTokens.AccessToken)

	refresh := performRequest(t, handler, http.MethodPost, "/api/v1/auth/refresh",
		`{"refreshToken":"`+loginTokens.RefreshToken+`"}`,
		map[string]string{"Content-Type": "application/json"})
	assertStatus(t, refresh.Code, http.StatusOK, refresh.Body.String())
	rotatedTokens := decodeTokenPair(t, refresh.Body.Bytes())
	if rotatedTokens.RefreshToken == loginTokens.RefreshToken {
		t.Fatal("expected refresh token rotation")
	}

	logout := performRequest(t, handler, http.MethodPost, "/api/v1/auth/logout",
		`{"refreshToken":"`+rotatedTokens.RefreshToken+`"}`,
		map[string]string{"Content-Type": "application/json"})
	assertStatus(t, logout.Code, http.StatusNoContent, logout.Body.String())

	accessAfterLogout := performRequest(t, handler, http.MethodGet, "/api/v1/users/me", "",
		map[string]string{"Authorization": "Bearer " + rotatedTokens.AccessToken})
	assertStatus(t, accessAfterLogout.Code, http.StatusOK, accessAfterLogout.Body.String())

	refreshAfterLogout := performRequest(t, handler, http.MethodPost, "/api/v1/auth/refresh",
		`{"refreshToken":"`+rotatedTokens.RefreshToken+`"}`,
		map[string]string{"Content-Type": "application/json"})
	assertStatus(t, refreshAfterLogout.Code, http.StatusUnauthorized, refreshAfterLogout.Body.String())
}

type tokenPair struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func decodeTokenPair(t *testing.T, body []byte) tokenPair {
	t.Helper()
	var pair tokenPair
	if err := json.Unmarshal(body, &pair); err != nil {
		t.Fatalf("decode token pair: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("expected access and refresh tokens, got %+v", pair)
	}
	return pair
}

func validateAccessTokenFromHTTPJWKS(t *testing.T, handler http.Handler, accessToken string) {
	t.Helper()
	response := performRequest(t, handler, http.MethodGet, "/.well-known/jwks.json", "", nil)
	assertStatus(t, response.Code, http.StatusOK, response.Body.String())
	var jwks struct {
		Keys []token.JWK `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected one JWK, got %d", len(jwks.Keys))
	}
	modulus, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	if err != nil {
		t.Fatalf("decode JWK modulus: %v", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	if err != nil {
		t.Fatalf("decode JWK exponent: %v", err)
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 + int(value)
	}
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	parsed, err := jwt.Parse(accessToken, func(parsed *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("integration-auth-service"))
	if err != nil || !parsed.Valid {
		t.Fatalf("validate access token using HTTP JWKS: valid=%t err=%v", parsed != nil && parsed.Valid, err)
	}
}

func assertStatus(t *testing.T, got, want int, body string) {
	t.Helper()
	if got != want {
		t.Fatalf("expected status %d, got %d: %s", want, got, body)
	}
}
