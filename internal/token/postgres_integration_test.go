package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/joaovv-Vitor/go-auth-service/internal/testsupport"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

func TestConcurrentRefreshRotationAllowsOneSuccessAndRevokesReusedFamily(t *testing.T) {
	database := testsupport.OpenPostgres(t)
	ctx := context.Background()
	userID := insertTestUser(t, database, "rotation@example.com")
	store := NewStore(database.Pool)
	presented, initial, err := NewRefreshToken(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("create initial refresh token: %v", err)
	}
	if err := store.Create(ctx, userID, initial); err != nil {
		t.Fatalf("persist initial refresh token: %v", err)
	}

	type result struct {
		refresh string
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			_, refresh, rotateErr := store.Rotate(ctx, presented)
			results <- result{refresh: refresh, err: rotateErr}
		}()
	}
	ready.Wait()
	close(start)

	first := <-results
	second := <-results
	close(results)
	var successfulRefresh string
	var successCount, reuseCount int
	for _, outcome := range []result{first, second} {
		switch {
		case outcome.err == nil:
			successCount++
			successfulRefresh = outcome.refresh
		case errors.Is(outcome.err, ErrRefreshTokenReuse):
			reuseCount++
		default:
			t.Fatalf("unexpected rotation result: %v", outcome.err)
		}
	}
	if successCount != 1 || reuseCount != 1 {
		t.Fatalf("expected one success and one reuse detection, got success=%d reuse=%d", successCount, reuseCount)
	}
	if _, _, err := store.Rotate(ctx, successfulRefresh); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected reused family to be revoked, got %v", err)
	}
}

func TestRefreshRotationRollsBackWhenLinkingTokensFails(t *testing.T) {
	database := testsupport.OpenPostgres(t)
	ctx := context.Background()
	userID := insertTestUser(t, database, "rollback@example.com")
	store := NewStore(database.Pool)
	presented, initial, err := NewRefreshToken(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("create initial refresh token: %v", err)
	}
	if err := store.Create(ctx, userID, initial); err != nil {
		t.Fatalf("persist initial refresh token: %v", err)
	}

	_, err = database.Pool.Exec(ctx, `
		CREATE FUNCTION fail_refresh_link() RETURNS trigger AS $$
		BEGIN
			IF NEW.replaced_by_token_id IS NOT NULL THEN
				RAISE EXCEPTION 'injected refresh link failure';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql
	`)
	if err != nil {
		t.Fatalf("create failure function: %v", err)
	}
	_, err = database.Pool.Exec(ctx, `
		CREATE TRIGGER fail_refresh_link_trigger
		BEFORE UPDATE ON refresh_tokens
		FOR EACH ROW EXECUTE FUNCTION fail_refresh_link()
	`)
	if err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	if _, _, err := store.Rotate(ctx, presented); err == nil {
		t.Fatal("expected injected rotation failure")
	}

	var tokenCount, usedCount, revokedCount int
	err = database.Pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(used_at), COUNT(revoked_at)
		FROM refresh_tokens
		WHERE family_id = $1
	`, initial.FamilyID).Scan(&tokenCount, &usedCount, &revokedCount)
	if err != nil {
		t.Fatalf("inspect rolled back rotation: %v", err)
	}
	if tokenCount != 1 || usedCount != 0 || revokedCount != 0 {
		t.Fatalf("expected untouched initial token after rollback, got tokens=%d used=%d revoked=%d", tokenCount, usedCount, revokedCount)
	}

	if _, err := database.Pool.Exec(ctx, `DROP TRIGGER fail_refresh_link_trigger ON refresh_tokens`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	if _, err := database.Pool.Exec(ctx, `DROP FUNCTION fail_refresh_link()`); err != nil {
		t.Fatalf("drop failure function: %v", err)
	}
	if _, _, err := store.Rotate(ctx, presented); err != nil {
		t.Fatalf("expected initial token to remain usable after rollback: %v", err)
	}
}

func TestLogoutRevokesEveryRefreshTokenInFamily(t *testing.T) {
	database := testsupport.OpenPostgres(t)
	ctx := context.Background()
	userID := insertTestUser(t, database, "logout@example.com")
	store := NewStore(database.Pool)
	presented, initial, err := NewRefreshToken(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("create initial refresh token: %v", err)
	}
	if err := store.Create(ctx, userID, initial); err != nil {
		t.Fatalf("persist initial refresh token: %v", err)
	}
	_, rotated, err := store.Rotate(ctx, presented)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if err := store.Revoke(ctx, rotated); err != nil {
		t.Fatalf("logout refresh family: %v", err)
	}
	if _, _, err := store.Rotate(ctx, rotated); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected rotated token to be revoked after logout, got %v", err)
	}
	if _, _, err := store.Rotate(ctx, presented); !errors.Is(err, ErrRefreshTokenReuse) {
		t.Fatalf("expected original token reuse to remain detectable, got %v", err)
	}
}

func TestLogoutDoesNotInvalidateAlreadyIssuedAccessToken(t *testing.T) {
	database := testsupport.OpenPostgres(t)
	ctx := context.Background()
	userID := insertTestUser(t, database, "stateless-access@example.com")
	store := NewStore(database.Pool)
	presented, refresh, err := NewRefreshToken(7 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if err := store.Create(ctx, userID, refresh); err != nil {
		t.Fatalf("persist refresh token: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer := NewSigner(privateKey, &privateKey.PublicKey, "integration-auth-service", "auth-api", 15*time.Minute)
	accessToken, err := signer.Issue(user.User{ID: userID, Email: "stateless-access@example.com", Role: user.RoleUser})
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}

	if err := store.Revoke(ctx, presented); err != nil {
		t.Fatalf("logout refresh family: %v", err)
	}
	if _, err := signer.Validate(accessToken); err != nil {
		t.Fatalf("expected access token to remain valid after logout: %v", err)
	}
	if _, _, err := store.Rotate(ctx, presented); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected refresh token to be revoked after logout, got %v", err)
	}
}

func insertTestUser(t *testing.T, database *testsupport.Postgres, email string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := database.Pool.Exec(context.Background(), `
		INSERT INTO users (id, name, email, password_hash, role)
		VALUES ($1, 'Integration User', $2, 'argon2id-phc', 'USER')
	`, id, email)
	if err != nil {
		t.Fatalf("insert integration user: %v", err)
	}
	return id
}
