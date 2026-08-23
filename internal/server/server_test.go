package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

type authenticatorStub struct {
	logoutErr error
}

func (authenticatorStub) Login(context.Context, auth.LoginInput) (auth.LoginResponse, error) {
	return auth.LoginResponse{}, errors.New("not implemented")
}

func (authenticatorStub) Refresh(context.Context, string) (auth.LoginResponse, error) {
	return auth.LoginResponse{}, errors.New("not implemented")
}

func (s authenticatorStub) Logout(context.Context, string) error { return s.logoutErr }

func (v verifierStub) Validate(string) (*token.Claims, error) {
	return v.claims, v.err
}

func (registererStub) Register(_ context.Context, input auth.RegisterInput) (user.User, error) {
	return user.User{ID: uuid.New(), Name: input.Name, Email: input.Email, Role: user.RoleUser}, nil
}

func performRequest(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(method, path, strings.NewReader(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestHealthEndpoint(t *testing.T) {
	response := performRequest(t, NewHandler(config.Config{AppEnv: "test"}, Dependencies{}), http.MethodGet, "/health", "", nil)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
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
	handler := NewHandler(config.Config{AppEnv: "test"}, Dependencies{})

	for _, path := range []string{"/openapi.json", "/docs", "/.well-known/jwks.json"} {
		response := performRequest(t, handler, http.MethodGet, path, "", nil)

		if response.Code != http.StatusOK {
			t.Fatalf("expected %s to return 200, got %d", path, response.Code)
		}
	}
}

func TestOpenAPIDocumentsBearerAuthentication(t *testing.T) {
	response := performRequest(t, NewHandler(config.Config{AppEnv: "test"}, Dependencies{}), http.MethodGet, "/openapi.json", "", nil)

	var document struct {
		Components struct {
			SecuritySchemes map[string]struct {
				Type         string `json:"type"`
				Scheme       string `json:"scheme"`
				BearerFormat string `json:"bearerFormat"`
			} `json:"securitySchemes"`
		} `json:"components"`
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode OpenAPI document: %v", err)
	}
	scheme, ok := document.Components.SecuritySchemes["bearerAuth"]
	if !ok || scheme.Type != "http" || scheme.Scheme != "bearer" || scheme.BearerFormat != "JWT" {
		t.Fatalf("unexpected bearerAuth scheme: %+v", scheme)
	}
	operation, ok := document.Paths["/api/v1/users/me"][strings.ToLower(http.MethodGet)]
	if !ok || len(operation.Security) != 1 {
		t.Fatalf("expected /api/v1/users/me to require bearerAuth: %+v", operation.Security)
	}
	if _, ok := operation.Security[0]["bearerAuth"]; !ok {
		t.Fatalf("expected bearerAuth operation security: %+v", operation.Security)
	}
}

func TestRegisterEndpoint(t *testing.T) {
	response := performRequest(t,
		NewHandler(config.Config{AppEnv: "test"}, Dependencies{Registerer: registererStub{}}),
		http.MethodPost,
		"/api/v1/auth/register",
		`{"name":"João","email":"joao@example.com","password":"a-strong-password"}`,
		map[string]string{"Content-Type": "application/json"},
	)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", response.Code)
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

func TestValidationErrorUsesStableModelWithoutInputValue(t *testing.T) {
	response := performRequest(t,
		NewHandler(config.Config{AppEnv: "test"}, Dependencies{Registerer: registererStub{}}),
		http.MethodPost,
		"/api/v1/auth/register",
		`{"name":"João","email":"invalid","password":"secret"}`,
		map[string]string{"Content-Type": "application/json"},
	)

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read validation error: %v", err)
	}
	var body struct {
		Error   string `json:"error"`
		Details []struct {
			Message string `json:"message"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rawBody, &body); err != nil {
		t.Fatalf("decode validation error: %v", err)
	}
	if body.Error != "validation_error" || len(body.Details) == 0 {
		t.Fatalf("unexpected validation error: %+v", body)
	}
	if strings.Contains(string(rawBody), "secret") {
		t.Fatal("validation response must not include the submitted password")
	}
}

func TestCurrentUserRequiresValidBearerToken(t *testing.T) {
	handler := NewHandler(config.Config{AppEnv: "test"}, Dependencies{
		TokenVerifier: verifierStub{err: errors.New("invalid token")},
	})

	response := performRequest(t, handler, http.MethodGet, "/api/v1/users/me", "", nil)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", response.Code)
	}
}

func TestCurrentUserReturnsTokenIdentity(t *testing.T) {
	userID := uuid.NewString()
	handler := NewHandler(config.Config{AppEnv: "test"}, Dependencies{
		TokenVerifier: verifierStub{claims: &token.Claims{
			Email: "joao@example.com",
			Roles: []string{user.RoleUser},
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: userID,
			},
		}},
	})

	response := performRequest(t, handler, http.MethodGet, "/api/v1/users/me", "", map[string]string{"Authorization": "Bearer access-token"})
	if response.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.Code)
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

func TestLogoutReturnsNoContentAndDoesNotCache(t *testing.T) {
	handler := NewHandler(config.Config{AppEnv: "test"}, Dependencies{Authenticator: authenticatorStub{}})
	response := performRequest(t,
		handler,
		http.MethodPost,
		"/api/v1/auth/logout",
		`{"refreshToken":"opaque-token"}`,
		map[string]string{"Content-Type": "application/json"},
	)

	if response.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", response.Header().Get("Cache-Control"))
	}
}

func TestLogoutUnknownTokenReturnsGenericStableError(t *testing.T) {
	handler := NewHandler(config.Config{AppEnv: "test"}, Dependencies{
		Authenticator: authenticatorStub{logoutErr: auth.ErrInvalidRefresh},
	})
	response := performRequest(t,
		handler,
		http.MethodPost,
		"/api/v1/auth/logout",
		`{"refreshToken":"unknown-secret-token"}`,
		map[string]string{"Content-Type": "application/json"},
	)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "unknown-secret-token") {
		t.Fatal("logout error must not echo the refresh token")
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode logout error: %v", err)
	}
	if body.Error != "invalid_token" {
		t.Fatalf("expected stable invalid_token error, got %q", body.Error)
	}
}
