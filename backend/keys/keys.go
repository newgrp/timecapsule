// Package keys associates times to P-256 keypairs.
package keys

import (
	"crypto/ecdh"
	"time"
)

// KeyManager associates times to P-256 key pairs.
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

// Returns the P-256 key pair for the given time.
//
// Times are normalized to UTC time internally, so different time.Time values that refer to the
// same absolute time are guaranteed to correspond to the same key.
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
