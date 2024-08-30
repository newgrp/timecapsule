package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

var zeroScalar = make([]byte, curve25519.ScalarSize)

// Derives a Curve 25519 EC private key from an initial secret and a time.
//
// The key derivation is deterministic.
func deriveKeyForTime(ikm []byte, t time.Time) (*ecdh.PrivateKey, error) {
	var info bytes.Buffer
	if err := binary.Write(&info, binary.BigEndian, t.Unix()); err != nil {
		// We should never fail to write an int64 to the buffer.
		return nil, err
	}
	stream := hkdf.New(sha256.New, ikm, nil, info.Bytes())

	scalar := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(stream, scalar); err != nil {
		return nil, fmt.Errorf("failed to read key from HKDF stream: %w", err)
	}
	if subtle.ConstantTimeCompare(scalar, zeroScalar) == 1 {
		return nil, fmt.Errorf("failed to read key from HKDF stream")
	}

	key, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("HKDF generated invalid key: %w", err)
	}
	return key, nil
}
