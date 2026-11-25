package checkpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

// Key errors. They never contain key material.
var (
	ErrKeyPermissions = errors.New("key: private key file permissions too open (want 0600 or stricter)")
	ErrKeyFormat      = errors.New("key: not a valid Ed25519 PEM key")
	ErrKeyNotRegular  = errors.New("key: not a regular file")
)

// maxKeyFile bounds how much of a key file is read.
const maxKeyFile = 64 << 10

// GenerateKey creates a new Ed25519 key and writes it to path with mode 0600.
// It fails if path already exists. The public key is returned.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	// Enforce 0600 even under a permissive umask-independent creation path.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return pub, f.Close()
}

// LoadPrivateKey loads a PKCS#8 PEM Ed25519 private key. It refuses files that
// grant any permission to group or others. The mode is checked on the open file
// descriptor to avoid a check/use race.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, ErrKeyNotRegular
	}
	if err := checkKeyPermissions(f, st, path); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, ErrKeyFormat
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrKeyFormat // do not wrap: parser errors could echo input
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrKeyFormat
	}
	return priv, nil
}

// MarshalPublicKey returns the PKIX PEM encoding of pub.
func MarshalPublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePublicKey parses a PKIX PEM Ed25519 public key.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, ErrKeyFormat
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrKeyFormat
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, ErrKeyFormat
	}
	return pub, nil
}

// LoadPublicKey reads a PKIX PEM Ed25519 public key file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}
