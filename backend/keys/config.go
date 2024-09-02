package keys

import (
	"fmt"
	"os"
	"strings"
)

// A source for a PKI configuration variable.
type configSource interface {
	// Reads the configuration value from the source.
	Get() (value string, ok bool, err error)
	// Writes a new value to the source.
	Set(value string) error
}

// An in-memory string source. Only allows new values to be written if the string is empty.
type memSource struct {
	str string
}

func newMemSource(str string) *memSource {
	return &memSource{str}
}

func (m *memSource) Get() (string, bool, error) {
	if m.str == "" {
		return "", false, nil
	}
	return m.str, true, nil
}

func (m *memSource) Set(value string) error {
	if m.str != "" && value != m.str {
		return fmt.Errorf("inferred value differs from specified value: got %s, want %s", value, m.str)
	}

	m.str = value
	return nil
}

// A file on disk. Only allows new values to be written if the file does not exist.
//
// This source trims leading and trailing whitespace when reading the file, but ensures that the
// file is stored with a newline at the end.
type fileSource struct {
	path string
}

func newFileSource(path string) *fileSource {
	return &fileSource{path}
}

func (f *fileSource) Get() (string, bool, error) {
	b, ok, err := tryReadFile(f.path)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	return strings.TrimSpace(string(b)), true, nil
}

func (f *fileSource) Set(value string) error {
	b, ok, err := tryReadFile(f.path)
	if err != nil {
		return err
	}
	if ok && strings.TrimSpace(value) != strings.TrimSpace(string(b)) {
		return fmt.Errorf("inferred value differs from value at %s: got %s, want %s", f.path, strings.TrimSpace(value), strings.TrimSpace(string(b)))
	}

	if value != "" && value[len(value)-1] != '\n' {
		value = fmt.Sprintf("%s\n", value)
	}
	return os.WriteFile(f.path, []byte(value), fileMode)
}

// A function that generates a new value. Writing to this source is a no-op.
type genSource func() (string, error)

func newGenSource(f func() (string, error)) *genSource {
	g := genSource(f)
	return &g
}

func (g *genSource) Get() (string, bool, error) {
	value, err := (*g)()
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (g *genSource) Set(string) error {
	return nil
}

// Synchronizes a configuration value between various sources.
//
// Tries to read the value from each source in order, stopping at the first success. Then, writes
// the value to all sources.
func syncrhonizeConfig(sources ...configSource) (string, error) {
	var value string
	for _, src := range sources {
		v, ok, err := src.Get()
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		value = v
		break
	}
	if value == "" {
		return "", fmt.Errorf("value could not be determined from any source")
	}

	for _, src := range sources {
		if err := src.Set(value); err != nil {
			return "", err
		}
	}
	return value, nil
}
