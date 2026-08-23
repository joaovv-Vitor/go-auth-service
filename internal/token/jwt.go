package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authclock "github.com/joaovv-Vitor/go-auth-service/internal/clock"
	"github.com/joaovv-Vitor/go-auth-service/internal/user"
)

type Claims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

type Signer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	ttl        time.Duration
	kid        string
	clock      authclock.Clock
}

func LoadSigner(privatePath, publicPath, issuer, audience string, ttl time.Duration) (*Signer, error) {
	privateBytes, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("read JWT private key: %w", err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("read JWT public key: %w", err)
	}

	privateKey, err := parsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	publicKey, err := parsePublicKey(publicBytes)
	if err != nil {
		return nil, err
	}
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E {
		return nil, errors.New("JWT private and public keys do not match")
	}
	if privateKey.N.BitLen() < 2048 {
		return nil, errors.New("JWT RSA key must be at least 2048 bits")
	}
	if issuer == "" || audience == "" || ttl <= 0 {
		return nil, errors.New("JWT issuer, audience and TTL are required")
	}

	return NewSigner(privateKey, publicKey, issuer, audience, ttl), nil
}

func NewSigner(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer, audience string, ttl time.Duration) *Signer {
	return NewSignerWithClock(privateKey, publicKey, issuer, audience, ttl, authclock.System{})
}

func NewSignerWithClock(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, issuer, audience string, ttl time.Duration, clock authclock.Clock) *Signer {
	if clock == nil {
		clock = authclock.System{}
	}
	return &Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
		ttl:        ttl,
		kid:        keyID(publicKey),
		clock:      clock,
	}
}

func (s *Signer) Issue(user user.User) (string, error) {
	now := s.clock.Now()
	claims := Claims{
		Email: user.Email,
		Roles: []string{user.Role},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{s.audience},
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.privateKey)
}

func (s *Signer) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

func (s *Signer) KeyID() string {
	return s.kid
}

type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

func (s *Signer) PublicJWK() JWK {
	var exponent [8]byte
	binary.BigEndian.PutUint64(exponent[:], uint64(s.publicKey.E))
	return JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(trimLeadingZeros(exponent[:])),
		Use: "sig",
		Alg: "RS256",
		Kid: s.kid,
	}
}

func (s *Signer) Validate(tokenString string) (*Claims, error) {
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected JWT signing method")
		}
		if kid, ok := t.Header["kid"].(string); !ok || kid != s.kid {
			return nil, errors.New("unexpected JWT key id")
		}
		return s.publicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.clock.Now))
	if err != nil || !parsed.Valid {
		if err == nil {
			err = errors.New("invalid JWT")
		}
		return nil, err
	}
	if claims.Subject == "" || claims.Email == "" || len(claims.Roles) == 0 || claims.IssuedAt == nil {
		return nil, errors.New("JWT is missing required claims")
	}
	return claims, nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid JWT private key PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse JWT private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("JWT private key is not RSA")
	}
	return rsaKey, nil
}

func parsePublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid JWT public key PEM")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse JWT public key: %w", err)
	}
	return key, nil
}

func keyID(publicKey *rsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())[:16]
}

func trimLeadingZeros(data []byte) []byte {
	for len(data) > 1 && data[0] == 0 {
		data = data[1:]
	}
	return data
}
