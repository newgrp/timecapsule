// Package keys associates times to P-256 keypairs.
package keys

import (
	"crypto/ecdh"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type PKIOptions struct {
	Name    string
	ID      uuid.UUID
	MinTime time.Time
	MaxTime time.Time
}

// KeyManager associates times to P-256 key pairs.
type KeyManager struct {
	minTime time.Time
	maxTime time.Time
	secrets *secretManager
}

// Constructs a new key manager using the given working directory for root
// secrets.
func NewKeyManager(options PKIOptions, secretsDir string) (*KeyManager, error) {
	secrets, err := newSecretManager(options, secretsDir)
	if err != nil {
		return nil, err
	}
	return &KeyManager{
		minTime: options.MinTime,
		maxTime: options.MaxTime,
		secrets: secrets,
	}, nil
}

// The PKI name of this key manager.
func (m *KeyManager) Name() string {
	return m.secrets.Name()
}

// The PKI ID of this key manager.
func (m *KeyManager) PKIID() uuid.UUID {
	return m.secrets.PKIID()
}

// Returns the P-256 key pair for the given time.
//
// Times are normalized to UTC time internally, so different time.Time values that refer to the
// same absolute time are guaranteed to correspond to the same key.
func (m *KeyManager) GetKeyForTime(t time.Time) (*ecdh.PrivateKey, error) {
	secret, err := m.secrets.GetSecretForTime(t)
	if err != nil {
		return nil, fmt.Errorf("failed to determine secret for %s: %+v", t.Format(time.RFC3339), err)
	}
	key, err := deriveKeyForTime(secret, t)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keypair for %s: %+v", t.Format(time.RFC3339), err)
	}
	return key, nil
}
