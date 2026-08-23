package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv              string
	HTTPAddr            string
	ShutdownTimeout     time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64
	DatabaseURL         string
	APIDocsEnabled      bool
	JWTIssuer           string
	JWTPublicKeyPath    string
	JWTPrivateKeyPath   string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	Argon2MemoryKiB     uint32
	Argon2Iterations    uint32
	Argon2Parallelism   uint8
}

func Load() (Config, error) {
	appEnv := getEnv("APP_ENV", "development")
	shutdownTimeout, err := durationEnv("SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	readTimeout, err := durationEnv("HTTP_READ_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := durationEnv("HTTP_WRITE_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := durationEnv("HTTP_IDLE_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
	}
	accessTokenTTL, err := durationEnv("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return Config{}, err
	}
	refreshTokenTTL, err := durationEnv("REFRESH_TOKEN_TTL", 720*time.Hour)
	if err != nil {
		return Config{}, err
	}
	maxRequestBodyBytes, err := positiveInt64Env("HTTP_MAX_BODY_BYTES", 64*1024)
	if err != nil {
		return Config{}, err
	}
	apiDocsEnabled, err := boolEnv("API_DOCS_ENABLED", !strings.EqualFold(appEnv, "production"))
	if err != nil {
		return Config{}, err
	}
	argon2MemoryKiB, err := boundedUintEnv("ARGON2_MEMORY_KIB", 64*1024, 8*1024, 1024*1024)
	if err != nil {
		return Config{}, err
	}
	argon2Iterations, err := boundedUintEnv("ARGON2_ITERATIONS", 3, 1, 10)
	if err != nil {
		return Config{}, err
	}
	argon2Parallelism, err := boundedUintEnv("ARGON2_PARALLELISM", 2, 1, 16)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		AppEnv:              appEnv,
		HTTPAddr:            getEnv("HTTP_ADDR", ":8080"),
		ShutdownTimeout:     shutdownTimeout,
		ReadTimeout:         readTimeout,
		WriteTimeout:        writeTimeout,
		IdleTimeout:         idleTimeout,
		MaxRequestBodyBytes: maxRequestBodyBytes,
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/auth_service?sslmode=disable"),
		APIDocsEnabled:      apiDocsEnabled,
		JWTIssuer:           getEnv("JWT_ISSUER", "auth-service"),
		JWTPublicKeyPath:    getEnv("JWT_PUBLIC_KEY_PATH", "certs/jwt.public.pem"),
		JWTPrivateKeyPath:   getEnv("JWT_PRIVATE_KEY_PATH", "certs/jwt.private.pem"),
		AccessTokenTTL:      accessTokenTTL,
		RefreshTokenTTL:     refreshTokenTTL,
		Argon2MemoryKiB:     uint32(argon2MemoryKiB),
		Argon2Iterations:    uint32(argon2Iterations),
		Argon2Parallelism:   uint8(argon2Parallelism),
	}

	if strings.TrimSpace(cfg.HTTPAddr) == "" {
		return Config{}, fmt.Errorf("HTTP_ADDR cannot be empty")
	}
	if cfg.ShutdownTimeout <= 0 || cfg.ReadTimeout <= 0 || cfg.WriteTimeout <= 0 || cfg.IdleTimeout <= 0 {
		return Config{}, fmt.Errorf("HTTP timeouts must be greater than zero")
	}
	if cfg.AccessTokenTTL <= 0 || cfg.RefreshTokenTTL <= 0 {
		return Config{}, fmt.Errorf("token TTLs must be greater than zero")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}

	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}

	return value, nil
}

func positiveInt64Env(key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return value, nil
}

func boolEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return value, nil
}

func boundedUintEnv(key string, fallback, minimum, maximum uint64) (uint64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minimum, maximum)
	}
	return value, nil
}
