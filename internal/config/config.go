package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	AppEnv            string
	HTTPAddr          string
	ShutdownTimeout   time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	DatabaseURL       string
	JWTIssuer         string
	JWTPublicKeyPath  string
	JWTPrivateKeyPath string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		AppEnv:            getEnv("APP_ENV", "development"),
		HTTPAddr:          getEnv("HTTP_ADDR", ":8080"),
		ShutdownTimeout:   mustDuration("SHUTDOWN_TIMEOUT", 10*time.Second),
		ReadTimeout:       mustDuration("HTTP_READ_TIMEOUT", 5*time.Second),
		WriteTimeout:      mustDuration("HTTP_WRITE_TIMEOUT", 10*time.Second),
		IdleTimeout:       mustDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable"),
		JWTIssuer:         getEnv("JWT_ISSUER", "auth-service"),
		JWTPublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "certs/jwt.public.pem"),
		JWTPrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "certs/jwt.private.pem"),
		AccessTokenTTL:    mustDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL:   mustDuration("REFRESH_TOKEN_TTL", 720*time.Hour),
	}

	if strings.TrimSpace(cfg.HTTPAddr) == "" {
		return Config{}, fmt.Errorf("HTTP_ADDR cannot be empty")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}

	return fallback
}

func mustDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}

	return value
}
