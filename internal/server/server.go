package server

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/joaovv-Vitor/go-auth-service/internal/config"
)

func New(cfg config.Config) *http.Server {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)

	api := humachi.New(router, huma.DefaultConfig("Go Auth Service", "0.1.0"))
	registerRoutes(api, cfg)

	return &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
}

func registerRoutes(api huma.API, cfg config.Config) {
	type healthOutput struct {
		Body struct {
			Status string `json:"status" doc:"Current service status" example:"ok"`
			Env    string `json:"env" doc:"Current application environment" example:"development"`
			Time   string `json:"time" format:"date-time" doc:"UTC response timestamp"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Check service health",
		Tags:        []string{"System"},
	}, func(ctx context.Context, input *struct{}) (*healthOutput, error) {
		output := &healthOutput{}
		output.Body.Status = "ok"
		output.Body.Env = cfg.AppEnv
		output.Body.Time = time.Now().UTC().Format(time.RFC3339)
		return output, nil
	})

	type jwksOutput struct {
		Body struct {
			Keys []any `json:"keys" doc:"JSON Web Keys used to validate access tokens"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID: "get-jwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/jwks.json",
		Summary:     "Get public signing keys",
		Tags:        []string{"Authentication"},
	}, func(ctx context.Context, input *struct{}) (*jwksOutput, error) {
		output := &jwksOutput{}
		output.Body.Keys = []any{}
		return output, nil
	})
}
