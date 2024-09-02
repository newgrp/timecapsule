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

	"github.com/google/uuid"
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

	// Creation mode for info and secret files.
	fileMode = 0o400
)

// Reads a file from disk, separating non-existence from other errors.
func tryReadFile(path string) (contents []byte, exists bool, err error) {
	contents, err = os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return contents, true, nil
}

// Creates a secret file and reports any errors to the callback channel.
func createSecretFileInternal(path string, done chan<- error) {
	secret := make([]byte, secretSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		done <- fmt.Errorf("insufficient entropy: %w", err)
	}
	if err := os.WriteFile(path, secret, fileMode); err != nil {
		done <- fmt.Errorf("failed to write secret file %s: %w", path, err)
	}
	done <- nil
}

// Associates each time with a root secret.
type secretManager struct {
	dir string

	name  string
	pkiID uuid.UUID

	writersMu sync.RWMutex
	writers   map[string]<-chan error
}

// Constructs a new secret manager using the given working directory.
func newSecretManager(options PKIOptions, dir string) (*secretManager, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to initialize secrets directory: %w", err)
	}

	name, err := syncrhonizeConfig(
		newMemSource(options.Name),
		newFileSource(path.Join(dir, "name")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to determine PKI name: %w", err)
	}

	mem := options.ID.String()
	if (options.ID == uuid.UUID{}) {
		mem = ""
	}
	idStr, err := syncrhonizeConfig(
		newMemSource(mem),
		newFileSource(path.Join(dir, "uuid")),
		newGenSource(func() (string, error) {
			return uuid.NewString(), nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to determine PKI ID: %w", err)
	}
	pkiID, err := uuid.Parse(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid UUID: %w", err)
	}

	return &secretManager{dir: dir, name: name, pkiID: pkiID, writers: make(map[string]<-chan error)}, nil
}

// The PKI name of this directory.
func (s *secretManager) Name() string {
	return s.name
}

// The PKI ID of this directory.
func (s *secretManager) PKIID() uuid.UUID {
	return s.pkiID
}

// Creates a new secret file. Returns the new secret.
func (s *secretManager) createSecretFile(path string) ([]byte, error) {
	var done chan error
	{
		s.writersMu.Lock()
		defer s.writersMu.Unlock()

		if ch, ok := s.writers[path]; ok {
			if err := <-ch; err != nil {
				return nil, err
			}
		}

		done = make(chan error, 1)
		s.writers[path] = done
	}

	go createSecretFileInternal(path, done)
	if err := <-done; err != nil {
		return nil, err
	}
	return os.ReadFile(path)
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

	secret, ok, err := tryReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secret file %s is corrupted: %w", path, err)
	}
	if ok {
		return secret, nil
	}
	return s.createSecretFile(path)
}
