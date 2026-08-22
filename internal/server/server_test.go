package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/auth"
	"github.com/joaovv-Vitor/go-auth-service/internal/config"
	"github.com/joaovv-Vitor/go-auth-service/internal/token"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

type registererStub struct{}

type verifierStub struct {
	claims *token.Claims
	err    error
}

func (v verifierStub) Validate(string) (*token.Claims, error) {
	return v.claims, v.err
}

func (registererStub) Register(_ context.Context, input auth.RegisterInput) (user.User, error) {
	return user.User{ID: uuid.New(), Name: input.Name, Email: input.Email, Role: user.RoleUser}, nil
}

func TestHealthEndpoint(t *testing.T) {
	server := httptest.NewServer(NewHandler(config.Config{AppEnv: "test"}, Dependencies{}))
	defer server.Close()

	response, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("get health: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}

	var body struct {
		Status string `json:"status"`
		Env    string `json:"env"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if body.Status != "ok" || body.Env != "test" {
		t.Fatalf("unexpected health response: %+v", body)
	}
}

func TestOpenAPIAndJWKSAndDocsAreAvailable(t *testing.T) {
	server := httptest.NewServer(NewHandler(config.Config{AppEnv: "test"}, Dependencies{}))
	defer server.Close()

	for _, path := range []string{"/openapi.json", "/docs", "/.well-known/jwks.json"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		response.Body.Close()

		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected %s to return 200, got %d", path, response.StatusCode)
		}
	}
}

func TestRegisterEndpoint(t *testing.T) {
	server := httptest.NewServer(NewHandler(config.Config{AppEnv: "test"}, Dependencies{Registerer: registererStub{}}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/register", strings.NewReader(`{"name":"João","email":"joao@example.com","password":"a-strong-password"}`))
	if err != nil {
		t.Fatalf("create register request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", response.StatusCode)
	}

	var body struct {
		Name         string `json:"name"`
		PasswordHash string `json:"password_hash"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if body.Name != "João" || body.PasswordHash != "" {
		t.Fatalf("unexpected register response: %+v", body)
	}
}

func TestCurrentUserRequiresValidBearerToken(t *testing.T) {
	server := httptest.NewServer(NewHandler(config.Config{AppEnv: "test"}, Dependencies{
		TokenVerifier: verifierStub{err: errors.New("invalid token")},
	}))
	defer server.Close()

	response, err := http.Get(server.URL + "/api/v1/users/me")
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", response.StatusCode)
	}
}

func TestCurrentUserReturnsTokenIdentity(t *testing.T) {
	userID := uuid.NewString()
	server := httptest.NewServer(NewHandler(config.Config{AppEnv: "test"}, Dependencies{
		TokenVerifier: verifierStub{claims: &token.Claims{
			Email: "joao@example.com",
			Roles: []string{user.RoleUser},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: userID,
			},
		}},
	}))
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/users/me", nil)
	if err != nil {
		t.Fatalf("create current user request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer access-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("get current user: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}

	var body struct {
		ID    string   `json:"id"`
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode current user: %v", err)
	}
	if body.ID != userID || body.Email != "joao@example.com" || len(body.Roles) != 1 {
		t.Fatalf("unexpected current user response: %+v", body)
	}
}
