package config

import "testing"

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("HTTP_READ_TIMEOUT", "not-a-duration")

	_, err := Load()
	if err == nil {
		t.Fatal("expected invalid duration error")
	}
}

func TestLoadUsesDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("API_DOCS_ENABLED", "")
	t.Setenv("HTTP_MAX_BODY_BYTES", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("expected default HTTP address, got %q", cfg.HTTPAddr)
	}
	if !cfg.APIDocsEnabled || cfg.MaxRequestBodyBytes != 64*1024 {
		t.Fatalf("unexpected HTTP defaults: docs=%t maxBody=%d", cfg.APIDocsEnabled, cfg.MaxRequestBodyBytes)
	}
	if cfg.Argon2MemoryKiB != 64*1024 || cfg.Argon2Iterations != 3 || cfg.Argon2Parallelism != 2 {
		t.Fatalf("unexpected Argon2id defaults: memory=%d iterations=%d parallelism=%d",
			cfg.Argon2MemoryKiB, cfg.Argon2Iterations, cfg.Argon2Parallelism)
	}
}

func TestLoadDisablesAPIDocsByDefaultInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("API_DOCS_ENABLED", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load production config: %v", err)
	}
	if cfg.APIDocsEnabled {
		t.Fatal("expected API docs to be disabled by default in production")
	}
}

func TestLoadRejectsInvalidHTTPHardeningConfiguration(t *testing.T) {
	t.Run("body limit", func(t *testing.T) {
		t.Setenv("HTTP_MAX_BODY_BYTES", "0")
		if _, err := Load(); err == nil {
			t.Fatal("expected invalid body limit error")
		}
	})
	t.Run("docs flag", func(t *testing.T) {
		t.Setenv("API_DOCS_ENABLED", "sometimes")
		if _, err := Load(); err == nil {
			t.Fatal("expected invalid docs flag error")
		}
	})
}

func TestLoadValidatesArgon2idParameters(t *testing.T) {
	t.Setenv("ARGON2_MEMORY_KIB", "4096")
	if _, err := Load(); err == nil {
		t.Fatal("expected unsafe Argon2id memory configuration to fail")
	}

	t.Setenv("ARGON2_MEMORY_KIB", "32768")
	t.Setenv("ARGON2_ITERATIONS", "4")
	t.Setenv("ARGON2_PARALLELISM", "1")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load custom Argon2id configuration: %v", err)
	}
	if cfg.Argon2MemoryKiB != 32768 || cfg.Argon2Iterations != 4 || cfg.Argon2Parallelism != 1 {
		t.Fatalf("unexpected custom Argon2id configuration: %+v", cfg)
	}
}
