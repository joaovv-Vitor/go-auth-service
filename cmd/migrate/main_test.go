package main

import "testing"

func TestPGXMigrationURL(t *testing.T) {
	got := pgxMigrationURL("postgres://postgres:postgres@localhost/auth_service?sslmode=disable")
	want := "pgx5://postgres:postgres@localhost/auth_service?sslmode=disable"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
