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
	"io"

	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/chart/loader/archive"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	loaderv2 "helm.sh/helm/v4/pkg/chart/v2/loader"
)

// FileLoader wraps Helm's loader.FileLoader to implement the
// secureloader interface.
type FileLoader string

func (f FileLoader) Load() (*chart.Chart, error) {
	l := loader.FileLoader(f)
	c, err := l.Load()
	if err != nil {
		return nil, err
	}
	return c.(*chart.Chart), nil
}

// LoadFile loads from an archive file.
func LoadFile(name string) (*chart.Chart, error) {
	return loaderv2.LoadFile(name)
}

// LoadArchiveFiles reads in files out of an archive into memory. This function
// performs important path security checks and should always be used before
// expanding a tarball
func LoadArchiveFiles(in io.Reader) ([]*archive.BufferedFile, error) {
	return archive.LoadArchiveFiles(in)
}

// LoadArchive loads from a reader containing a compressed tar archive.
func LoadArchive(in io.Reader) (*chart.Chart, error) {
	return loaderv2.LoadArchive(in)
}
