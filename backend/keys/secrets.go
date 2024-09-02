package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
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

// Creates or reads a file as a string.
//
// If the file already exists, createOrReadFile checks that it has the expected contents (modulo
// leading and trailing whitespace). If the file does not exist, it is created with the given
// contents, plus a newline if the contents don't already end with one.
func createOrReadFile(path string, contents string) (string, error) {
	finishReadFile := func(got, want string) (string, error) {
		got = strings.TrimSpace(got)
		want = strings.TrimSpace(want)
		if got != want {
			return "", fmt.Errorf("file did not have expected contents: got %s, want %s", got, want)
		}
		return got, nil
	}
	createFile := func(path, contents string) error {
		if contents == "" || contents[len(contents)-1] != '\n' {
			contents = fmt.Sprintf("%s\n", contents)
		}
		if err := os.WriteFile(path, []byte(contents), fileMode); err != nil {
			return err
		}
		return nil
	}

	got, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err == nil {
		return finishReadFile(string(got), contents)
	}

	if err = createFile(path, contents); err != nil {
		return "", err
	}
	return contents, nil
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

	name, err := createOrReadFile(path.Join(dir, "name"), options.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create/read name file: %w", err)
	}

	pkiID := options.ID
	if (pkiID == uuid.UUID{}) {
		pkiID = uuid.New()
	}
	idStr, err := createOrReadFile(path.Join(dir, "uuid"), pkiID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create/read uuid file: %w", err)
	}
	pkiID, err = uuid.Parse(idStr)
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

// Reads a secret file from disk, or false if no such file exists.
func (s *secretManager) readSecretFile(path string) (secret []byte, exists bool, err error) {
	secret, err = os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("secret file %s is corrupted: %w", path, err)
	}
	return secret, true, nil
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

	secret, ok, err := s.readSecretFile(path)
	if err != nil {
		return nil, err
	}
	if ok {
		return secret, nil
	}
	return s.createSecretFile(path)
}
