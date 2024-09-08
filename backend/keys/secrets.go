package keys

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path"
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
	secretMode = 0o400
)

// Associates each time with a root secret.
type secretManager struct {
	dir string

	name  string
	pkiID uuid.UUID
}

// Constructs a new secret manager using the given working directory.
func newSecretManager(options PKIOptions, dir string) (*secretManager, error) {
	// Create secrets directory if it does not already exist.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to initialize secrets directory: %w", err)
	}

	// Detemine PKI name. Fail if the name is not provided by at least one of `options`` and "name"
	// file.
	name, err := syncrhonizeConfig(
		newMemSource(options.Name),
		newFileSource(path.Join(dir, "name")),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to determine PKI name: %w", err)
	}

	// Determine PKI ID. This can be provided by `options`, the "uuid" file, or generated
	// internally.
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

	// Ensure that all secrets we might need exist.
	for t := options.MinTime.UTC().Truncate(secretInterval); t.Compare(options.MaxTime) <= 0; t = t.Add(secretInterval) {
		path := path.Join(dir, t.Format(fileNameLayout))

		_, ok, err := tryReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("secret file %s is corrupted: %w", path, err)
		}
		if ok {
			continue
		}

		secret := make([]byte, secretSize)
		if _, err := io.ReadFull(rand.Reader, secret); err != nil {
			return nil, fmt.Errorf("insufficient entropy: %w", err)
		}
		if err := os.WriteFile(path, secret, secretMode); err != nil {
			return nil, fmt.Errorf("failed to write secret file %s: %w", path, err)
		}
	}

	return &secretManager{dir: dir, name: name, pkiID: pkiID}, nil
}

// The PKI name of this directory.
func (s *secretManager) Name() string {
	return s.name
}

// The PKI ID of this directory.
func (s *secretManager) PKIID() uuid.UUID {
	return s.pkiID
}

// Returns the root secret for the given time.
//
// Different times may share a root secret.
//
// Times are normalized to UTC time internally, so different time.Time values representing the same
// absolute time are guaranteed to have the same root secret.
func (s *secretManager) GetSecretForTime(t time.Time) ([]byte, error) {
	file := t.Truncate(secretInterval).UTC().Format(fileNameLayout)
	secret, err := os.ReadFile(path.Join(s.dir, file))
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file %s: %w", file, err)
	}
	return secret, nil
}
