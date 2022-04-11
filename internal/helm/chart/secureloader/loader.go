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
*/

package secureloader

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"

	"github.com/fluxcd/source-controller/internal/helm"
)

// Loader returns a new loader.ChartLoader appropriate for the given chart
// name. That being, SecureDirLoader when name is a directory, and
// FileLoader when it's a file.
// Name can be an absolute or relative path, but always has to be inside
// root.
func Loader(root, name string) (loader.ChartLoader, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	relName := filepath.Clean(name)
	if filepath.IsAbs(relName) {
		var err error
		if relName, err = filepath.Rel(root, name); err != nil {
			return nil, err
		}
	}

	secureName, err := securejoin.SecureJoin(root, relName)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(secureName)
	if err != nil {
		if pathErr := new(fs.PathError); errors.As(err, &pathErr) {
			return nil, &fs.PathError{Op: pathErr.Op, Path: strings.TrimPrefix(secureName, root), Err: pathErr.Err}
		}
		return nil, err
	}

	if fi.IsDir() {
		return NewSecureDirLoader(root, relName, helm.MaxChartFileSize), nil
	}
	return FileLoader(secureName), nil
}

// Load takes a string root and name, tries to resolve it to a file or directory,
// and then loads it securely without traversing outside of root.
//
// This is the preferred way to load a chart. It will discover the chart encoding
// and hand off to the appropriate chart reader.
//
// If a .helmignore file is present, the directory loader will skip loading any files
// matching it. But .helmignore is not evaluated when reading out of an archive.
func Load(root, name string) (*chart.Chart, error) {
	l, err := Loader(root, name)
	if err != nil {
		return nil, err
	}
	return l.Load()
}
