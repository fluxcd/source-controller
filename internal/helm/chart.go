/*
Copyright 2020 The Flux authors

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

package helm

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"sigs.k8s.io/yaml"
)

// OverwriteChartDefaultValues overwrites the chart default values file with the given data.
func OverwriteChartDefaultValues(chart *helmchart.Chart, data []byte) (bool, error) {
	// Read override values file data
	values, err := chartutil.ReadValues(data)
	if err != nil {
		return false, fmt.Errorf("failed to parse provided override values file data")
	}

	// Replace current values file in Raw field
	for _, f := range chart.Raw {
		if f.Name == chartutil.ValuesfileName {
			// Do nothing if contents are equal
			if reflect.DeepEqual(f.Data, data) {
				return false, nil
			}

			// Replace in Files field
			for _, f := range chart.Files {
				if f.Name == chartutil.ValuesfileName {
					f.Data = data
				}
			}

			f.Data = data
			chart.Values = values
			return true, nil
		}
	}

	// This should never happen, helm charts must have a values.yaml file to be valid
	return false, fmt.Errorf("failed to locate values file: %s", chartutil.ValuesfileName)
}

// LoadChartMetadata attempts to load the chart.Metadata from the "Chart.yaml" file in the directory or archive at the
// given chartPath. It takes "requirements.yaml" files into account, and is therefore compatible with the
// chart.APIVersionV1 format.
func LoadChartMetadata(chartPath string) (*helmchart.Metadata, error) {
	i, err := os.Stat(chartPath)
	if err != nil {
		return nil, err
	}
	switch {
	case i.IsDir():
		return LoadChartMetadataFromDir(chartPath)
	default:
		return LoadChartMetadataFromArchive(chartPath)
	}
}

// LoadChartMetadataFromDir loads the chart.Metadata from the "Chart.yaml" file in the directory at the given path.
// It takes "requirements.yaml" files into account, and is therefore compatible with the chart.APIVersionV1 format.
func LoadChartMetadataFromDir(dir string) (*helmchart.Metadata, error) {
	m := new(helmchart.Metadata)

	b, err := os.ReadFile(filepath.Join(dir, chartutil.ChartfileName))
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(b, m)
	if err != nil {
		return nil, fmt.Errorf("cannot load '%s': %w", chartutil.ChartfileName, err)
	}
	if m.APIVersion == "" {
		m.APIVersion = helmchart.APIVersionV1
	}

	b, err = os.ReadFile(filepath.Join(dir, "requirements.yaml"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(b) > 0 {
		if err = yaml.Unmarshal(b, m); err != nil {
			return nil, fmt.Errorf("cannot load 'requirements.yaml': %w", err)
		}
	}
	return m, nil
}

// LoadChartMetadataFromArchive loads the chart.Metadata from the "Chart.yaml" file in the archive at the given path.
// It takes "requirements.yaml" files into account, and is therefore compatible with the chart.APIVersionV1 format.
func LoadChartMetadataFromArchive(archive string) (*helmchart.Metadata, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)

	var m *helmchart.Metadata
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if hd.FileInfo().IsDir() {
			// Use this instead of hd.Typeflag because we don't have to do any
			// inference chasing.
			continue
		}

		switch hd.Typeflag {
		// We don't want to process these extension header files.
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		}

		// Archive could contain \ if generated on Windows
		delimiter := "/"
		if strings.ContainsRune(hd.Name, '\\') {
			delimiter = "\\"
		}
		parts := strings.Split(hd.Name, delimiter)

		// We are only interested in files in the base directory
		if len(parts) != 2 {
			continue
		}

		// Normalize the path to the / delimiter
		n := strings.Join(parts[1:], delimiter)
		n = strings.ReplaceAll(n, delimiter, "/")
		n = path.Clean(n)

		switch parts[1] {
		case chartutil.ChartfileName, "requirements.yaml":
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			if m == nil {
				m = new(helmchart.Metadata)
			}
			err = yaml.Unmarshal(b, m)
			if err != nil {
				return nil, fmt.Errorf("cannot load '%s': %w", parts[1], err)
			}
			if m.APIVersion == "" {
				m.APIVersion = helmchart.APIVersionV1
			}
		}
	}
	if m == nil {
		return nil, fmt.Errorf("no '%s' found", chartutil.ChartfileName)
	}
	return m, nil
}
