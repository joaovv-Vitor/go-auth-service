package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	phcAlgorithm = "argon2id"
	phcVersion   = "v=19"
	saltSize     = 16
	keySize      = 32
)

type Hasher struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

func DefaultHasher() Hasher {
	return Hasher{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
	}
}

func (h Hasher) Hash(plainText string) (string, error) {
	if err := h.validate(); err != nil {
		return "", err
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	key := argon2.IDKey([]byte(plainText), salt, h.Iterations, h.Memory, h.Parallelism, keySize)
	encode := base64.RawStdEncoding
	return fmt.Sprintf("$%s$%s$m=%d,t=%d,p=%d$%s$%s",
		phcAlgorithm,
		phcVersion,
		h.Memory,
		h.Iterations,
		h.Parallelism,
		encode.EncodeToString(salt),
		encode.EncodeToString(key),
	), nil
}

func (h Hasher) Verify(plainText, encodedHash string) (bool, error) {
	return Verify(plainText, encodedHash)
}

func Verify(plainText, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != phcAlgorithm || parts[2] != phcVersion {
		return false, errors.New("invalid argon2id hash format")
	}

	var memory uint32
	var iterations uint32
	var parallelism uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, errors.New("invalid argon2id parameters")
	}
	if memory == 0 || iterations == 0 || parallelism == 0 || parallelism > 255 {
		return false, errors.New("invalid argon2id parameters")
	}

	decode := base64.RawStdEncoding
	salt, err := decode.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, errors.New("invalid argon2id salt")
	}
	expected, err := decode.DecodeString(parts[5])
	if err != nil || len(expected) == 0 {
		return false, errors.New("invalid argon2id key")
	}

	actual := argon2.IDKey([]byte(plainText), salt, iterations, uint32(memory), uint8(parallelism), uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func (h Hasher) validate() error {
	if h.Memory == 0 || h.Iterations == 0 || h.Parallelism == 0 {
		return errors.New("argon2id parameters must be greater than zero")
	}
	return nil
}
