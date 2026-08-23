package password

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hasher := DefaultHasher()
	hash, err := hasher.Hash("a-strong-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	valid, err := Verify("a-strong-password", hash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !valid {
		t.Fatal("expected password to be valid")
	}

	valid, err = Verify("another-password", hash)
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if valid {
		t.Fatal("expected wrong password to be invalid")
	}
}

func TestHashUsesUniqueSalts(t *testing.T) {
	hasher := DefaultHasher()
	first, err := hasher.Hash("a-strong-password")
	if err != nil {
		t.Fatalf("hash first password: %v", err)
	}
	second, err := hasher.Hash("a-strong-password")
	if err != nil {
		t.Fatalf("hash second password: %v", err)
	}
	if first == second {
		t.Fatal("expected different hashes for the same password")
	}
}

func TestHasherRejectsInvalidParameters(t *testing.T) {
	tests := []Hasher{
		{Iterations: 1, Parallelism: 1},
		{Memory: 64 * 1024, Parallelism: 1},
		{Memory: 64 * 1024, Iterations: 1},
	}
	for _, hasher := range tests {
		if _, err := hasher.Hash("test-only-password"); err == nil {
			t.Fatalf("expected invalid parameters to be rejected: %+v", hasher)
		}
	}
}

func TestVerifyRejectsMalformedPHCWithoutPanic(t *testing.T) {
	validSalt := "MDEyMzQ1Njc4OWFiY2RlZg"
	tests := []string{
		"",
		"not-a-phc-hash",
		"$argon2i$v=19$m=65536,t=3,p=2$" + validSalt + "$a2V5",
		"$argon2id$v=16$m=65536,t=3,p=2$" + validSalt + "$a2V5",
		"$argon2id$v=19$invalid$" + validSalt + "$a2V5",
		"$argon2id$v=19$m=0,t=3,p=2$" + validSalt + "$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=256$" + validSalt + "$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=2$short$a2V5",
		"$argon2id$v=19$m=65536,t=3,p=2$" + validSalt + "$not-base64!",
		strings.Repeat("$", 10),
	}
	for _, encoded := range tests {
		if valid, err := Verify("test-only-password", encoded); err == nil || valid {
			t.Fatalf("expected malformed PHC %q to be rejected, got valid=%t err=%v", encoded, valid, err)
		}
	}
}
