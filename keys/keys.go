// Package keys associates times to Curve 25519 keypairs.
package keys

import (
	"crypto/ecdh"
	"time"
)

// KeyManager associates times to Curve 25519 keypairs.
type KeyManager struct {
	secrets *secretManager
}

// Constructs a new key manager using the given working directory for root
// secrets.
func NewKeyManager(secretsDir string) (*KeyManager, error) {
	secrets, err := newSecretManager(secretsDir)
	if err != nil {
		return nil, err
	}
	return &KeyManager{secrets}, nil
}

// Returns the DER-encoded Curve25519 private key for the given time.
//
// Times are normalized to UTC time internally, so different time.Time values
// that refer to the same absolute time are guaranteed to correspond to the same
// key.
func (m *KeyManager) GetKeyForTime(t time.Time) (*ecdh.PrivateKey, error) {
	secret, err := m.secrets.GetSecretForTime(t)
	if err != nil {
		return nil, err
	}
	key, err := deriveKeyForTime(secret, t)
	if err != nil {
		return nil, err
	}
	return key, nil
}
