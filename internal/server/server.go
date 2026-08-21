package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/joaovv-Vitor/go-auth-service/internal/auth"
	"github.com/joaovv-Vitor/go-auth-service/internal/config"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

type Dependencies struct {
	Database   Pinger
	Registerer auth.Registerer
}

func New(cfg config.Config, deps Dependencies) *http.Server {
	return &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      NewHandler(cfg, deps),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
}

func NewHandler(cfg config.Config, deps Dependencies) http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)
	router.Use(requestLogger(slog.Default()))

	apiConfig := huma.DefaultConfig("Go Auth Service", "0.1.0")
	apiConfig.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
		},
	}
	api := humachi.New(router, apiConfig)
	registerRoutes(api, cfg, deps)

	return router
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

type Pinger interface {
	Ping(context.Context) error
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startedAt := time.Now()
			writer := &responseWriter{ResponseWriter: w}
			next.ServeHTTP(writer, r)

			logger.InfoContext(r.Context(), "http request",
				"request_id", middleware.GetReqID(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", responseStatus(writer.status),
				"duration", time.Since(startedAt).String(),
			)
		})
	}
}

func responseStatus(status int) int {
	if status == 0 {
		return http.StatusOK
	}
	return status
}

func registerRoutes(api huma.API, cfg config.Config, deps Dependencies) {
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
		Errors:      []int{http.StatusServiceUnavailable},
	}, func(ctx context.Context, input *struct{}) (*healthOutput, error) {
		output := &healthOutput{}
		output.Body.Status = "ok"
		output.Body.Env = cfg.AppEnv
		output.Body.Time = time.Now().UTC().Format(time.RFC3339)
		if deps.Database != nil {
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := deps.Database.Ping(pingCtx); err != nil {
				return nil, huma.Error503ServiceUnavailable("database unavailable")
			}
		}
		return output, nil
	})

	type registerInput struct {
		Body struct {
			Name     string `json:"name" minLength:"1" maxLength:"120" doc:"User's display name" example:"João"`
			Email    string `json:"email" format:"email" maxLength:"320" doc:"User's email address" example:"joao@example.com"`
			Password string `json:"password" minLength:"12" maxLength:"128" doc:"User's password" example:"senha-segura-123"`
		}
	}
	type registerOutput struct {
		Body struct {
			ID    string   `json:"id" format:"uuid" doc:"User identifier"`
			Name  string   `json:"name"`
			Email string   `json:"email" format:"email"`
			Roles []string `json:"roles"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:   "post-register",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/register",
		Summary:       "Register a user",
		Tags:          []string{"Authentication"},
		DefaultStatus: http.StatusCreated,
		Errors:        []int{http.StatusBadRequest, http.StatusConflict, http.StatusServiceUnavailable},
	}, func(ctx context.Context, input *registerInput) (*registerOutput, error) {
		if deps.Registerer == nil {
			return nil, huma.Error503ServiceUnavailable("authentication service unavailable")
		}

		created, err := deps.Registerer.Register(ctx, auth.RegisterInput{
			Name:     input.Body.Name,
			Email:    input.Body.Email,
			Password: input.Body.Password,
		})
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrInvalidRegistration):
				return nil, huma.Error400BadRequest("invalid registration")
			case errors.Is(err, user.ErrEmailAlreadyExists):
				return nil, huma.Error409Conflict("email already exists")
			case errors.Is(err, auth.ErrServiceUnavailable):
				return nil, huma.Error503ServiceUnavailable("authentication service unavailable")
			default:
				return nil, huma.Error500InternalServerError("could not register user")
			}
		}

		output := &registerOutput{}
		output.Body.ID = created.ID.String()
		output.Body.Name = created.Name
		output.Body.Email = created.Email
		output.Body.Roles = []string{created.Role}
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
