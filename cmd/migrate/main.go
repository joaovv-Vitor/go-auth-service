package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/joaovv-Vitor/go-auth-service/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	command := "up"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = "migrations"
	}

	runner, err := migrate.New("file://"+migrationsPath, pgxMigrationURL(cfg.DatabaseURL))
	if err != nil {
		log.Fatalf("create migration runner: %v", err)
	}
	defer func() {
		sourceErr, databaseErr := runner.Close()
		if sourceErr != nil || databaseErr != nil {
			log.Printf("close migration runner: source=%v database=%v", sourceErr, databaseErr)
		}
	}()

	if err := run(runner, command, os.Args[2:]); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("migrate %s: %v", command, err)
	}
	log.Printf("migration command %s completed", command)
}

type migrator interface {
	Up() error
	Steps(int) error
	Version() (uint, bool, error)
}

func run(runner migrator, command string, args []string) error {
	switch command {
	case "up":
		return runner.Up()
	case "down":
		steps := 1
		if len(args) > 0 {
			parsed, err := strconv.Atoi(args[0])
			if err != nil || parsed <= 0 {
				return errors.New("down steps must be a positive integer")
			}
			steps = parsed
		}
		return runner.Steps(-steps)
	case "version":
		version, dirty, err := runner.Version()
		if err != nil {
			return err
		}
		fmt.Printf("version=%d dirty=%t\n", version, dirty)
		return nil
	default:
		return fmt.Errorf("unsupported migration command %q", command)
	}
}

func pgxMigrationURL(databaseURL string) string {
	if strings.HasPrefix(databaseURL, "postgres://") {
		return "pgx5://" + strings.TrimPrefix(databaseURL, "postgres://")
	}
	if strings.HasPrefix(databaseURL, "postgresql://") {
		return "pgx5://" + strings.TrimPrefix(databaseURL, "postgresql://")
	}
	return databaseURL
}
