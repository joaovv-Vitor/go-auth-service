package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/auth"
	"github.com/joaovv-Vitor/go-auth-service/internal/config"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

type registererStub struct{}

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
