package keys

import (
	"errors"
	"io/fs"
	"os"
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
