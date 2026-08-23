package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joaovv-Vitor/go-auth-service/internal/testsupport"
)

func TestLoadSignerAcceptsSupportedPEMFormats(t *testing.T) {
	privateKey := testsupport.RSAKey(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS8 private key: %v", err)
	}

	tests := []struct {
		name       string
		privateDER []byte
		privatePEM string
		publicDER  []byte
		publicPEM  string
	}{
		{
			name:       "PKCS1 private and PKIX public",
			privateDER: x509.MarshalPKCS1PrivateKey(privateKey),
			privatePEM: "RSA PRIVATE KEY",
			publicDER:  mustMarshalPKIXPublicKey(t, &privateKey.PublicKey),
			publicPEM:  "PUBLIC KEY",
		},
		{
			name:       "PKCS8 private and PKCS1 public",
			privateDER: pkcs8,
			privatePEM: "PRIVATE KEY",
			publicDER:  x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
			publicPEM:  "RSA PUBLIC KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privatePath := writePEM(t, "jwt.private.pem", tt.privatePEM, tt.privateDER)
			publicPath := writePEM(t, "jwt.public.pem", tt.publicPEM, tt.publicDER)
			signer, err := LoadSigner(privatePath, publicPath, "auth-service", "auth-api", time.Minute)
			if err != nil {
				t.Fatalf("load signer: %v", err)
			}
			if signer.PublicKey().N.Cmp(privateKey.N) != 0 {
				t.Fatal("loaded signer has an unexpected public key")
			}
		})
	}
}

func TestLoadSignerRejectsInvalidKeyMaterial(t *testing.T) {
	privateKey := testsupport.RSAKey(t)
	privatePath := writePEM(t, "jwt.private.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))
	publicPath := writePEM(t, "jwt.public.pem", "PUBLIC KEY", mustMarshalPKIXPublicKey(t, &privateKey.PublicKey))
	otherKey := testsupport.RSAKey(t)
	mismatchedPublicPath := writePEM(t, "mismatched.public.pem", "PUBLIC KEY", mustMarshalPKIXPublicKey(t, &otherKey.PublicKey))
	malformedPath := filepath.Join(t.TempDir(), "malformed.pem")
	if err := os.WriteFile(malformedPath, []byte("not PEM"), 0o600); err != nil {
		t.Fatalf("write malformed key: %v", err)
	}

	shortKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate short RSA key: %v", err)
	}
	shortPrivatePath := writePEM(t, "short.private.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(shortKey))
	shortPublicPath := writePEM(t, "short.public.pem", "PUBLIC KEY", mustMarshalPKIXPublicKey(t, &shortKey.PublicKey))
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecdsaPrivateDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatalf("marshal ECDSA private key: %v", err)
	}
	ecdsaPublicDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ECDSA public key: %v", err)
	}
	ecdsaPrivatePath := writePEM(t, "ecdsa.private.pem", "PRIVATE KEY", ecdsaPrivateDER)
	ecdsaPublicPath := writePEM(t, "ecdsa.public.pem", "PUBLIC KEY", ecdsaPublicDER)

	tests := []struct {
		name        string
		privatePath string
		publicPath  string
		want        string
	}{
		{name: "missing private key", privatePath: filepath.Join(t.TempDir(), "missing.pem"), publicPath: publicPath, want: "read JWT private key"},
		{name: "missing public key", privatePath: privatePath, publicPath: filepath.Join(t.TempDir(), "missing.pem"), want: "read JWT public key"},
		{name: "malformed private key", privatePath: malformedPath, publicPath: publicPath, want: "invalid JWT private key PEM"},
		{name: "malformed public key", privatePath: privatePath, publicPath: malformedPath, want: "invalid JWT public key PEM"},
		{name: "mismatched pair", privatePath: privatePath, publicPath: mismatchedPublicPath, want: "do not match"},
		{name: "short RSA key", privatePath: shortPrivatePath, publicPath: shortPublicPath, want: "at least 2048 bits"},
		{name: "non-RSA private key", privatePath: ecdsaPrivatePath, publicPath: publicPath, want: "not RSA"},
		{name: "non-RSA public key", privatePath: privatePath, publicPath: ecdsaPublicPath, want: "parse JWT public key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadSigner(tt.privatePath, tt.publicPath, "auth-service", "auth-api", time.Minute)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestLoadSignerRejectsInvalidJWTConfiguration(t *testing.T) {
	privateKey := testsupport.RSAKey(t)
	privatePath := writePEM(t, "jwt.private.pem", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey))
	publicPath := writePEM(t, "jwt.public.pem", "PUBLIC KEY", mustMarshalPKIXPublicKey(t, &privateKey.PublicKey))

	tests := []struct {
		name     string
		issuer   string
		audience string
		ttl      time.Duration
	}{
		{name: "missing issuer", audience: "auth-api", ttl: time.Minute},
		{name: "missing audience", issuer: "auth-service", ttl: time.Minute},
		{name: "zero TTL", issuer: "auth-service", audience: "auth-api"},
		{name: "negative TTL", issuer: "auth-service", audience: "auth-api", ttl: -time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadSigner(privatePath, publicPath, tt.issuer, tt.audience, tt.ttl); err == nil {
				t.Fatal("expected invalid JWT configuration to be rejected")
			}
		})
	}
}

func writePEM(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func mustMarshalPKIXPublicKey(t *testing.T, publicKey *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}
	return der
}
