package testsupport

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testDatabaseEnv = "TEST_DATABASE_URL"

type Postgres struct {
	Pool     *pgxpool.Pool
	Migrator *migrate.Migrate
	Schema   string
}

// OpenPostgres creates a migration-backed, schema-isolated PostgreSQL test
// database. Integration tests are opt-in to prevent accidental use of a
// development or production database.
func OpenPostgres(t testing.TB) *Postgres {
	t.Helper()

	databaseURL := strings.TrimSpace(os.Getenv(testDatabaseEnv))
	if databaseURL == "" {
		t.Skipf("set %s to run PostgreSQL integration tests", testDatabaseEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping integration database: %v", err)
	}

	schema := "auth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create integration schema: %v", err)
	}

	var pool *pgxpool.Pool
	var runner *migrate.Migrate
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		if runner != nil {
			_, _ = runner.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		admin.Close()
	})

	schemaURL, err := withSearchPath(databaseURL, schema)
	if err != nil {
		t.Fatalf("configure integration schema: %v", err)
	}
	runner, err = migrate.New("file://"+migrationsPath(t), pgxMigrationURL(schemaURL))
	if err != nil {
		t.Fatalf("create integration migrator: %v", err)
	}
	if err := runner.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("apply integration migrations: %v", err)
	}

	pool, err = pgxpool.New(ctx, schemaURL)
	if err != nil {
		t.Fatalf("open schema integration pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping schema integration pool: %v", err)
	}

	return &Postgres{Pool: pool, Migrator: runner, Schema: schema}
}

func withSearchPath(databaseURL, schema string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
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

func migrationsPath(t testing.TB) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test support path")
	}
	path, err := filepath.Abs(filepath.Join(filepath.Dir(currentFile), "..", "..", "migrations"))
	if err != nil {
		t.Fatalf("resolve migrations path: %v", err)
	}
	return filepath.ToSlash(path)
}
