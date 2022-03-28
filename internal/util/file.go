/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/fluxcd/source-controller/internal/fs"
)

func writeBytesToFile(bytes []byte, file *os.File) error {
	if _, err := file.Write(bytes); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write to file %s: %w", file.Name(), err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

// Writes the provided bytes to a temp file with the name provided in the path and
// returns the file handle. If renameToOriginal is true, it renames the temp file to
// the intended file name (since temp file names have random bytes as suffix).
func WriteToTempFile(bytes []byte, out string, renameToOriginal bool) (*os.File, error) {
	file, err := os.CreateTemp("", filepath.Base(out))
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file %s: %w", filepath.Base(out), err)
	}
	err = writeBytesToFile(bytes, file)
	if err != nil {
		return nil, err
	}
	if renameToOriginal {
		err = fs.RenameWithFallback(file.Name(), filepath.Join("/tmp", filepath.Base(out)))
		file, err = os.Open(filepath.Join("/tmp", filepath.Base(out)))
		if err != nil {
			return nil, fmt.Errorf("failed to rename temporary file %s: %w", filepath.Base(out), err)
		}
	}
	return file, nil
}
