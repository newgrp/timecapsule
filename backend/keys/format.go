package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	pemTypePublicKey  = "PUBLIC KEY"
	pemTypePrivateKey = "PRIVATE KEY"
)

// Formats a public key as a PEM-encoded SubjectPublicKeyInfo message.
func FormatPublicKeyAsSPKIPEM(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypePublicKey,
		Bytes: der,
	})
	return string(p), nil
}

// Formats a public key as a PEM-encoded PrivateKeyInfo (a.k.a. PKCS #8) message.
func FormatPrivateKeyAsPKCS8PEM(priv any) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", err
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:  pemTypePrivateKey,
		Bytes: der,
	})
	return string(p), nil
}

// Parses a PEM-encoded SubjectPublicKeyInfo message as an ECDH public key.
func ParseECDHPublicKeyAsSPKIPEM(p string) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, fmt.Errorf("failed to parse public key as PEM block")
	}
	if block.Type != pemTypePublicKey {
		return nil, fmt.Errorf("public key has wrong PEM type: got %s, want %s", block.Type, pemTypePublicKey)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	switch v := parsed.(type) {
	case *ecdh.PublicKey:
		return v, nil
	case *ecdsa.PublicKey:
		pub, err := v.ECDH()
		if err != nil {
			return nil, fmt.Errorf("public key is invalid: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("public key is of unsupported type %T", parsed)
	}
}

// Parses a PEM-encoded PrivateKeyInfo (a.k.a. PKCS #8) message as an ECDH private key.
func ParseECDHPrivateKeyAsPKCS8PEM(p string) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key as PEM block")
	}
	if block.Type != pemTypePrivateKey {
		return nil, fmt.Errorf("private key has wrong PEM type: got %s, want %s", block.Type, pemTypePrivateKey)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS #8: %w", err)
	}
	switch v := parsed.(type) {
	case *ecdh.PrivateKey:
		return v, nil
	case *ecdsa.PrivateKey:
		priv, err := v.ECDH()
		if err != nil {
			return nil, fmt.Errorf("private key is invalid: %w", err)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("private key is of unsupported type %T", parsed)
	}
}
