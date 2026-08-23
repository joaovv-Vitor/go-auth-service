package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/joaovv-Vitor/go-auth-service/internal/auth"
	"github.com/joaovv-Vitor/go-auth-service/internal/config"
	"github.com/joaovv-Vitor/go-auth-service/internal/token"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

type Dependencies struct {
	Database      Pinger
	Registerer    auth.Registerer
	Authenticator auth.Authenticator
	JWKProvider   interface{ PublicJWK() token.JWK }
	TokenVerifier interface {
		Validate(string) (*token.Claims, error)
	}
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
	router.Use(middleware.ClientIPFromRemoteAddr)
	router.Use(middleware.Recoverer)
	router.Use(securityHeaders)
	router.Use(requestLogger(slog.Default()))

	apiConfig := huma.DefaultConfig("Go Auth Service", "0.1.0")
	if !cfg.APIDocsEnabled {
		apiConfig.OpenAPIPath = ""
		apiConfig.DocsPath = ""
		apiConfig.SchemasPath = ""
	}
	apiConfig.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
		},
	}
	api := humachi.New(router, apiConfig)
	api.UseMiddleware(authMiddleware(api, deps.TokenVerifier))
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

type claimsContextKey struct{}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(api huma.API, verifier interface {
	Validate(string) (*token.Claims, error)
}) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		requiresAuth := false
		for _, scheme := range ctx.Operation().Security {
			if _, ok := scheme["bearerAuth"]; ok {
				requiresAuth = true
				break
			}
		}
		if !requiresAuth {
			next(ctx)
			return
		}
		if verifier == nil {
			huma.WriteErr(api, ctx, http.StatusServiceUnavailable, "authentication service unavailable")
			return
		}
		header := ctx.Header("Authorization")
		if len(header) <= len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid token")
			return
		}
		claims, err := verifier.Validate(strings.TrimSpace(header[len("Bearer "):]))
		if err != nil {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid token")
			return
		}
		next(huma.WithValue(ctx, claimsContextKey{}, claims))
	}
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
				"client_ip", middleware.GetClientIP(r.Context()),
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
	maxRequestBodyBytes := cfg.MaxRequestBodyBytes
	if maxRequestBodyBytes <= 0 {
		maxRequestBodyBytes = 64 * 1024
	}
	type loginInput struct {
		Body struct {
			Email    string `json:"email" format:"email" maxLength:"320" doc:"User's email address" example:"joao@example.com"`
			Password string `json:"password" minLength:"1" maxLength:"128" doc:"User's password" example:"senha-segura-123"`
		}
	}
	type loginOutput struct {
		Body struct {
			AccessToken  string `json:"accessToken" doc:"Short-lived JWT access token" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.example.signature"`
			RefreshToken string `json:"refreshToken" doc:"Opaque refresh token" example:"550e8400-e29b-41d4-a716-446655440000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`
			TokenType    string `json:"tokenType" example:"Bearer"`
			ExpiresIn    int64  `json:"expiresIn" example:"900" doc:"Access token lifetime in seconds"`
		}
	}

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

	type refreshInput struct {
		Body struct {
			RefreshToken string `json:"refreshToken" minLength:"1" doc:"Opaque refresh token" example:"550e8400-e29b-41d4-a716-446655440000.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:  "post-refresh",
		Method:       http.MethodPost,
		Path:         "/api/v1/auth/refresh",
		Summary:      "Rotate a refresh token",
		Tags:         []string{"Authentication"},
		MaxBodyBytes: maxRequestBodyBytes,
		Errors:       []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
	}, func(ctx context.Context, input *refreshInput) (*loginOutput, error) {
		if deps.Authenticator == nil {
			return nil, huma.Error503ServiceUnavailable("authentication service unavailable")
		}
		result, err := deps.Authenticator.Refresh(ctx, input.Body.RefreshToken)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidRefresh) {
				return nil, huma.Error401Unauthorized("invalid refresh token")
			}
			return nil, huma.Error500InternalServerError("could not refresh session")
		}
		output := &loginOutput{}
		output.Body.AccessToken = result.AccessToken
		output.Body.RefreshToken = result.RefreshToken
		output.Body.TokenType = "Bearer"
		output.Body.ExpiresIn = result.ExpiresIn
		return output, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "post-logout",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/logout",
		Summary:       "Revoke a refresh token family",
		Tags:          []string{"Authentication"},
		MaxBodyBytes:  maxRequestBodyBytes,
		DefaultStatus: http.StatusNoContent,
		Errors:        []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
	}, func(ctx context.Context, input *refreshInput) (*struct{}, error) {
		if deps.Authenticator == nil {
			return nil, huma.Error503ServiceUnavailable("authentication service unavailable")
		}
		if err := deps.Authenticator.Logout(ctx, input.Body.RefreshToken); err != nil {
			return nil, huma.Error401Unauthorized("invalid refresh token")
		}
		return nil, nil
	})

	type currentUserOutput struct {
		Body struct {
			ID    string   `json:"id" format:"uuid" example:"550e8400-e29b-41d4-a716-446655440000"`
			Email string   `json:"email" format:"email" example:"joao@example.com"`
			Roles []string `json:"roles"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "get-current-user",
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me",
		Summary:     "Get the authenticated user",
		Tags:        []string{"Users"},
		Security:    []map[string][]string{{"bearerAuth": {}}},
		Errors:      []int{http.StatusUnauthorized},
	}, func(ctx context.Context, input *struct{}) (*currentUserOutput, error) {
		claims, ok := ctx.Value(claimsContextKey{}).(*token.Claims)
		if !ok || claims.Subject == "" {
			return nil, huma.Error401Unauthorized("invalid token")
		}
		output := &currentUserOutput{}
		output.Body.ID = claims.Subject
		output.Body.Email = claims.Email
		output.Body.Roles = claims.Roles
		return output, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "post-login",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/login",
		Summary:       "Authenticate a user",
		Tags:          []string{"Authentication"},
		MaxBodyBytes:  maxRequestBodyBytes,
		DefaultStatus: http.StatusOK,
		Errors:        []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
	}, func(ctx context.Context, input *loginInput) (*loginOutput, error) {
		if deps.Authenticator == nil {
			return nil, huma.Error503ServiceUnavailable("authentication service unavailable")
		}
		result, err := deps.Authenticator.Login(ctx, auth.LoginInput{
			Email:    input.Body.Email,
			Password: input.Body.Password,
		})
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				return nil, huma.Error401Unauthorized("invalid credentials")
			}
			return nil, huma.Error500InternalServerError("could not authenticate user")
		}
		output := &loginOutput{}
		output.Body.AccessToken = result.AccessToken
		output.Body.RefreshToken = result.RefreshToken
		output.Body.TokenType = "Bearer"
		output.Body.ExpiresIn = result.ExpiresIn
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
			ID    string   `json:"id" format:"uuid" doc:"User identifier" example:"550e8400-e29b-41d4-a716-446655440000"`
			Name  string   `json:"name" example:"João"`
			Email string   `json:"email" format:"email" example:"joao@example.com"`
			Roles []string `json:"roles"`
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:   "post-register",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/register",
		Summary:       "Register a user",
		Tags:          []string{"Authentication"},
		MaxBodyBytes:  maxRequestBodyBytes,
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
			Keys []token.JWK `json:"keys" doc:"JSON Web Keys used to validate access tokens"`
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
		if deps.JWKProvider != nil {
			output.Body.Keys = []token.JWK{deps.JWKProvider.PublicJWK()}
		} else {
			output.Body.Keys = []token.JWK{}
		}
		return output, nil
	})
}
