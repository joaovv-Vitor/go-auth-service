package password

import "testing"

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
