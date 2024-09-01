package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sync"
	"time"
)

const (
	// Size of each secret in bytes.
	secretSize = 32

	// Length of time that each secret covers.
	//
	// Secret intervals are also aligned to this period, with the Unix epoch considered to be the
	// zero time.
	secretInterval = time.Hour

	// Layout for time file names. See https://pkg.go.dev/time#Layout for context.
	//
	// Since *some* developers work on Windows, this must produce valid Windows file names. In
	// particular, the string cannot contain colons (":"), which rules out ~every standard time
	// format string.
	fileNameLayout = "2006-01-02@15.04.05"

	// Creation mode for secret files.
	secretMode = 0o400
)

// Associates each time with a root secret.
type secretManager struct {
	writeMu sync.Mutex
	dir     string
}

// Constructs a new secret manager using the given working directory.
func newSecretManager(dir string) (*secretManager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to initialize secrets directory: %w", err)
	}
	return &secretManager{writeMu: sync.Mutex{}, dir: dir}, nil
}

// Reads a secret file from disk, or false if no such file exists.
func (s *secretManager) readSecretFile(path string) (secret []byte, exists bool, err error) {
	// Another thread might be writing the file concurrently, so read in a loop until the secret is
	// the expected length.
	for len(secret) < secretSize {
		secret, err = os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("secret file %s is corrupted: %w", path, err)
		}
	}
	return secret, true, nil
}

// Creates a new secret file. Returns the new secret.
func (s *secretManager) createSecretFile(path string) ([]byte, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// First try to read the file, in case another thread created it before we acquired the lock.
	secret, ok, err := s.readSecretFile(path)
	if err != nil {
		return nil, err
	}
	if ok {
		return secret, nil
	}

	// The secret file does not exist, so we must create it.
	secret = make([]byte, secretSize)
	if _, err = io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("insufficient entropy: %w", err)
	}
	if err = os.WriteFile(path, secret, secretMode); err != nil {
		return nil, fmt.Errorf("failed to write secret file %s: %w", path, err)
	}
	return secret, nil
}

// Returns the root secret for the given time.
//
// Different times may share a root secret.
//
// Times are normalized to UTC time internally, so different time.Time values representing the same
// absolute time are guaranteed to have the same root secret.
func (s *secretManager) GetSecretForTime(t time.Time) ([]byte, error) {
	file := t.Truncate(secretInterval).UTC().Format(fileNameLayout)
	path := path.Join(s.dir, file)

	secret, ok, err := s.readSecretFile(path)
	if err != nil {
		return nil, err
	}
	if ok {
		return secret, nil
	}
	return s.createSecretFile(path)
}
