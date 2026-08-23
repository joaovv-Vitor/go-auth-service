package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joaovv-Vitor/go-auth-service/internal/auth"
	"github.com/joaovv-Vitor/go-auth-service/internal/config"
	"github.com/joaovv-Vitor/go-auth-service/internal/database"
	"github.com/joaovv-Vitor/go-auth-service/internal/password"
	"github.com/joaovv-Vitor/go-auth-service/internal/server"
	"github.com/joaovv-Vitor/go-auth-service/internal/token"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	databaseCtx, databaseCancel := context.WithTimeout(context.Background(), 10*time.Second)
	db, err := database.NewPool(databaseCtx, cfg.DatabaseURL)
	databaseCancel()
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer db.Close()

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := db.Ping(pingCtx); err != nil {
		pingCancel()
		log.Fatalf("ping database: %v", err)
	}
	pingCancel()

	signer, err := token.LoadSigner(cfg.JWTPrivateKeyPath, cfg.JWTPublicKeyPath, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL)
	if err != nil {
		log.Fatalf("load JWT keys: %v", err)
	}
	users := user.NewPostgresRepository(db)
	hasher := password.Hasher{
		Memory:      cfg.Argon2MemoryKiB,
		Iterations:  cfg.Argon2Iterations,
		Parallelism: cfg.Argon2Parallelism,
	}
	registerService := auth.NewService(users, hasher)
	loginService := auth.NewLoginService(users, hasher, signer, token.NewStore(db), cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	srv := server.New(cfg, server.Dependencies{
		Database:      db,
		Registerer:    registerService,
		Authenticator: loginService,
		JWKProvider:   signer,
		TokenVerifier: signer,
	})

	errCh := make(chan error, 1)
	go func() {
		log.Printf("http server listening on %s", cfg.HTTPAddr)
		errCh <- srv.ListenAndServe()
	}()

	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err = <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	case <-stopCtx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
		log.Fatalf("graceful shutdown: %v", shutdownErr)
	}

	log.Println("server stopped")
}
