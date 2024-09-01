package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const maxKeyAttempts = 10
const p256ScalarSize = 32

// Generates a P-256 key pair from a byte stream of entropy.
//
// This function is essentially the same as ecdh.P256().GenerateKey(), but is guaranteed to be
// stable.
func generateKeyStable(stream io.Reader) (*ecdh.PrivateKey, error) {
	// This "generate bytes and check" approach seems uncomfortably naive, but it is used by the Go
	// standard library and BoringSSL at time of writing. It is also recommended by FIPS 186-4
	// B.4.2.
	buf := make([]byte, p256ScalarSize)
	for i := 0; i < maxKeyAttempts; i++ {
		if _, err := io.ReadFull(stream, buf); err != nil {
			return nil, fmt.Errorf("ran out of entropy: %w", err)
		}
		if key, err := ecdh.P256().NewPrivateKey(buf); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("failed to generate a valid key in %d attempts", maxKeyAttempts)
}

// Derives a P-256 key pair from an initial secret and a time.
//
// The key derivation is deterministic and stable.
func deriveKeyForTime(ikm []byte, t time.Time) (*ecdh.PrivateKey, error) {
	var info bytes.Buffer
	if err := binary.Write(&info, binary.BigEndian, t.Unix()); err != nil {
		// We should never fail to write an int64 to the buffer.
		return nil, err
	}
	stream := hkdf.New(sha256.New, ikm, nil, info.Bytes())

	return generateKeyStable(stream)
}
