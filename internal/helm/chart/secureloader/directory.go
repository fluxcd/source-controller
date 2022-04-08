/*
Copyright The Helm Authors.
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

This file has been derived from
https://github.com/helm/helm/blob/v3.8.1/pkg/chart/loader/directory.go.

It has been modified to not blindly accept any resolved symlink path, but
instead check it against the configured root before allowing it to be included.
It also allows for capping the size of any file loaded into the chart.
*/

package secureloader

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"

	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader/ignore"
	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader/sympath"
)

var (
	// DefaultMaxFileSize is the default maximum file size of any chart file
	// loaded.
	DefaultMaxFileSize = 16 << 20 // 16MiB

	utf8bom = []byte{0xEF, 0xBB, 0xBF}
)

// SecureDirLoader securely loads a chart from a directory while resolving
// symlinks without including files outside root.
type SecureDirLoader struct {
	root    string
	dir     string
	maxSize int
}

// NewSecureDirLoader returns a new SecureDirLoader, configured to the scope of the
// root and provided dir. Max size configures the maximum size a file must not
// exceed to be loaded. If 0 it defaults to defaultMaxFileSize, it can be
// disabled using a negative integer.
func NewSecureDirLoader(root string, dir string, maxSize int) SecureDirLoader {
	if maxSize == 0 {
		maxSize = DefaultMaxFileSize
	}
	return SecureDirLoader{
		root:    root,
		dir:     dir,
		maxSize: maxSize,
	}
}

// Load loads and returns the chart.Chart, or an error.
func (l SecureDirLoader) Load() (*chart.Chart, error) {
	return SecureLoadDir(l.root, l.dir, l.maxSize)
}

// SecureLoadDir securely loads from a directory, without going outside root.
func SecureLoadDir(root, dir string, maxSize int) (*chart.Chart, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	topDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	// Confirm topDir is actually relative to root
	if _, err = isSecureSymlinkPath(root, topDir); err != nil {
		return nil, fmt.Errorf("cannot load chart from dir: %w", err)
	}

	// Just used for errors
	c := &chart.Chart{}

	// Get the absolute location of the .helmignore file
	relDirPath, err := filepath.Rel(root, topDir)
	if err != nil {
		// We are not expected to be returning this error, as the above call to
		// isSecureSymlinkPath already does the same. However, especially
		// because we are dealing with security aspects here, we check it
		// anyway in case this assumption changes.
		return nil, err
	}
	iFile, err := securejoin.SecureJoin(root, filepath.Join(relDirPath, ignore.HelmIgnore))

	// Load the .helmignore rules
	rules := ignore.Empty()
	if _, err = os.Stat(iFile); err == nil {
		r, err := ignore.ParseFile(iFile)
		if err != nil {
			return c, err
		}
		rules = r
	}
	rules.AddDefaults()

	var files []*loader.BufferedFile
	topDir += string(filepath.Separator)

	walk := func(name, absoluteName string, fi os.FileInfo, err error) error {
		n := strings.TrimPrefix(name, topDir)
		if n == "" {
			// No need to process top level. Avoid bug with helmignore .* matching
			// empty names. See issue 1779.
			return nil
		}

		// Normalize to / since it will also work on Windows
		n = filepath.ToSlash(n)

		if err != nil {
			return err
		}
		if fi.IsDir() {
			// Directory-based ignore rules should involve skipping the entire
			// contents of that directory.
			if rules.Ignore(n, fi) {
				return filepath.SkipDir
			}
			// Check after excluding ignores to provide the user with an option
			// to opt-out from including certain paths.
			if _, err := isSecureSymlinkPath(root, absoluteName); err != nil {
				return fmt.Errorf("cannot load '%s' directory: %w", n, err)
			}
			return nil
		}

		// If a .helmignore file matches, skip this file.
		if rules.Ignore(n, fi) {
			return nil
		}

		// Check after excluding ignores to provide the user with an option
		// to opt-out from including certain paths.
		if _, err := isSecureSymlinkPath(root, absoluteName); err != nil {
			return fmt.Errorf("cannot load '%s' file: %w", n, err)
		}

		// Irregular files include devices, sockets, and other uses of files that
		// are not regular files. In Go they have a file mode type bit set.
		// See https://golang.org/pkg/os/#FileMode for examples.
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("cannot load irregular file %s as it has file mode type bits set", n)
		}

		if fileSize := fi.Size(); maxSize > 0 && fileSize > int64(maxSize) {
			return fmt.Errorf("cannot load file %s as file size (%d) exceeds limit (%d)", n, fileSize, maxSize)
		}

		data, err := os.ReadFile(name)
		if err != nil {
			return fmt.Errorf("error reading %s: %w", n, err)
		}
		data = bytes.TrimPrefix(data, utf8bom)

		files = append(files, &loader.BufferedFile{Name: n, Data: data})
		return nil
	}
	if err = sympath.Walk(topDir, walk); err != nil {
		return c, err
	}
	return loader.LoadFiles(files)
}

// isSecureSymlinkPath attempts to make the given absolute path relative to
// root and securely joins this with root. If the result equals absolute path,
// it is safe to use.
func isSecureSymlinkPath(root, absPath string) (bool, error) {
	root, absPath = filepath.Clean(root), filepath.Clean(absPath)
	if root == "/" {
		return true, nil
	}
	unsafePath, err := filepath.Rel(root, absPath)
	if err != nil {
		return false, fmt.Errorf("cannot calculate path relative to root for resolved symlink")
	}
	safePath, err := securejoin.SecureJoin(root, unsafePath)
	if err != nil {
		return false, fmt.Errorf("cannot securely join root with resolved relative symlink path")
	}
	if safePath != absPath {
		return false, fmt.Errorf("symlink traverses outside root boundary: relative path to root %s", unsafePath)
	}
	return true, nil
}
