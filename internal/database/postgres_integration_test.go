package database_test

import (
	"context"
	"errors"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/joaovv-Vitor/go-auth-service/internal/testsupport"
)

func TestMigrationsApplyAndRollbackOnCleanSchema(t *testing.T) {
	database := testsupport.OpenPostgres(t)

	assertTableExists(t, database, "users", true)
	assertTableExists(t, database, "refresh_tokens", true)

	if err := database.Migrator.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("rollback migration: %v", err)
	}
	assertTableExists(t, database, "users", false)
	assertTableExists(t, database, "refresh_tokens", false)
}

func assertTableExists(t *testing.T, database *testsupport.Postgres, table string, expected bool) {
	t.Helper()
	var qualifiedName *string
	err := database.Pool.QueryRow(context.Background(), `SELECT to_regclass($1)`, database.Schema+"."+table).Scan(&qualifiedName)
	if err != nil {
		t.Fatalf("check table %s: %v", table, err)
	}
	if (qualifiedName != nil) != expected {
		t.Fatalf("expected table %s existence to be %t, got %v", table, expected, qualifiedName)
	}
}
