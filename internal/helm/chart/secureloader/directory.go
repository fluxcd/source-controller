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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"

	"github.com/fluxcd/source-controller/internal/helm"
	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader/ignore"
	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader/sympath"
)

var (
	utf8bom = []byte{0xEF, 0xBB, 0xBF}
)

// SecureDirLoader securely loads a chart from a directory while resolving
// symlinks without including files outside root.
type SecureDirLoader struct {
	root    string
	path    string
	maxSize int64
}

// NewSecureDirLoader returns a new SecureDirLoader, configured to the scope of the
// root and provided dir. Max size configures the maximum size a file must not
// exceed to be loaded. If 0 it defaults to helm.MaxChartFileSize, it can be
// disabled using a negative integer.
func NewSecureDirLoader(root string, path string, maxSize int64) SecureDirLoader {
	if maxSize == 0 {
		maxSize = helm.MaxChartFileSize
	}
	return SecureDirLoader{
		root:    root,
		path:    path,
		maxSize: maxSize,
	}
}

// Load loads and returns the chart.Chart, or an error.
func (l SecureDirLoader) Load() (*chart.Chart, error) {
	return SecureLoadDir(l.root, l.path, l.maxSize)
}

// SecureLoadDir securely loads a chart from the path relative to root, without
// traversing outside root. When maxSize >= 0, files are not allowed to exceed
// this size, or an error is returned.
func SecureLoadDir(root, path string, maxSize int64) (*chart.Chart, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	// Ensure path is relative
	if filepath.IsAbs(path) {
		relChartPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		path = relChartPath
	}

	// Resolve secure absolute path
	absChartName, err := securejoin.SecureJoin(root, path)
	if err != nil {
		return nil, err
	}

	// Load ignore rules
	rules, err := secureLoadIgnoreRules(root, path)
	if err != nil {
		return nil, fmt.Errorf("cannot load ignore rules for chart: %w", err)
	}

	// Lets go for a walk...
	fileWalker := newSecureFileWalker(root, absChartName, maxSize, rules)
	if err = sympath.Walk(fileWalker.absChartPath, fileWalker.walk); err != nil {
		return nil, fmt.Errorf("failed to load files from %s: %w", strings.TrimPrefix(fileWalker.absChartPath, fileWalker.root), err)
	}

	loaded, err := loader.LoadFiles(fileWalker.files)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart from %s: %w", strings.TrimPrefix(fileWalker.absChartPath, fileWalker.root), err)
	}
	return loaded, nil
}

// secureLoadIgnoreRules attempts to load the ignore.HelmIgnore file from the
// chart path relative to root. If the file is a symbolic link, it is evaluated
// with the given root treated as root of the filesystem.
// If the ignore file does not exist, or points to a location outside of root,
// default ignore.Rules are returned. Any error other than fs.ErrNotExist is
// returned.
func secureLoadIgnoreRules(root, chartPath string) (*ignore.Rules, error) {
	rules := ignore.Empty()

	iFile, err := securejoin.SecureJoin(root, filepath.Join(chartPath, ignore.HelmIgnore))
	if err != nil {
		return nil, err
	}
	_, err = os.Stat(iFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if rules, err = ignore.ParseFile(iFile); err != nil {
			return nil, err
		}
	}

	rules.AddDefaults()
	return rules, nil
}

// secureFileWalker does the actual walking over the directory, any file loaded
// by walk is appended to files.
type secureFileWalker struct {
	root         string
	absChartPath string
	maxSize      int64
	rules        *ignore.Rules
	files        []*loader.BufferedFile
}

func newSecureFileWalker(root, absChartPath string, maxSize int64, rules *ignore.Rules) *secureFileWalker {
	absChartPath = filepath.Clean(absChartPath) + string(filepath.Separator)
	return &secureFileWalker{
		root:         root,
		absChartPath: absChartPath,
		maxSize:      maxSize,
		rules:        rules,
		files:        make([]*loader.BufferedFile, 0),
	}
}

func (w *secureFileWalker) walk(name, absName string, fi os.FileInfo, err error) error {
	n := strings.TrimPrefix(name, w.absChartPath)
	if n == "" {
		// No need to process top level. Avoid bug with helmignore .* matching
		// empty names. See issue 1779.
		return nil
	}

	if err != nil {
		return err
	}

	// Normalize to / since it will also work on Windows
	n = filepath.ToSlash(n)

	if fi.IsDir() {
		// Directory-based ignore rules should involve skipping the entire
		// contents of that directory.
		if w.rules.Ignore(n, fi) {
			return filepath.SkipDir
		}
		// Check after excluding ignores to provide the user with an option
		// to opt-out from including certain paths.
		if _, err := isSecureAbsolutePath(w.root, absName); err != nil {
			return fmt.Errorf("cannot load '%s' directory: %w", n, err)
		}
		return nil
	}

	// If a .helmignore file matches, skip this file.
	if w.rules.Ignore(n, fi) {
		return nil
	}

	// Check after excluding ignores to provide the user with an option
	// to opt-out from including certain paths.
	if _, err := isSecureAbsolutePath(w.root, absName); err != nil {
		return fmt.Errorf("cannot load '%s' file: %w", n, err)
	}

	// Irregular files include devices, sockets, and other uses of files that
	// are not regular files. In Go they have a file mode type bit set.
	// See https://golang.org/pkg/os/#FileMode for examples.
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("cannot load irregular file %s as it has file mode type bits set", n)
	}

	// Confirm size it not outside boundaries
	if fileSize := fi.Size(); w.maxSize > 0 && fileSize > w.maxSize {
		return fmt.Errorf("cannot load file %s as file size (%d) exceeds limit (%d)", n, fileSize, w.maxSize)
	}

	data, err := os.ReadFile(absName)
	if err != nil {
		if pathErr := new(fs.PathError); errors.As(err, &pathErr) {
			err = &fs.PathError{Op: pathErr.Op, Path: strings.TrimPrefix(absName, w.root), Err: pathErr.Err}
		}
		return fmt.Errorf("error reading %s: %w", n, err)
	}
	data = bytes.TrimPrefix(data, utf8bom)

	w.files = append(w.files, &loader.BufferedFile{Name: n, Data: data})
	return nil
}

// isSecureAbsolutePath attempts to make the given absolute path relative to
// root and securely joins this with root. If the result equals absolute path,
// it is safe to use.
func isSecureAbsolutePath(root, absPath string) (bool, error) {
	root, absPath = filepath.Clean(root), filepath.Clean(absPath)
	if root == "/" {
		return true, nil
	}
	unsafePath, err := filepath.Rel(root, absPath)
	if err != nil {
		return false, fmt.Errorf("cannot calculate path relative to root for absolute path")
	}
	safePath, err := securejoin.SecureJoin(root, unsafePath)
	if err != nil {
		return false, fmt.Errorf("cannot securely join root with resolved relative path")
	}
	if safePath != absPath {
		return false, fmt.Errorf("absolute path traverses outside root boundary: relative path to root %s", unsafePath)
	}
	return true, nil
}
