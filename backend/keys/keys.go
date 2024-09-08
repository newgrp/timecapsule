// Package keys associates times to P-256 keypairs.
package keys

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrTimeOutOfRange = errors.New("time is out of range")

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
	if t.Compare(m.minTime) < 0 || t.Compare(m.maxTime) > 0 {
		return nil, fmt.Errorf("%w: only times between %s and %s are supported", ErrTimeOutOfRange, m.minTime.Format(time.RFC3339), m.maxTime.Format(time.RFC3339))
	}

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
