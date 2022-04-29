/*
Copyright 2021 The Flux authors

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

package chart

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/otiai10/copy"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"

	"github.com/fluxcd/source-controller/internal/helm"
)

var (
	// helmPackageFile contains the path to a Helm package in the v2 format
	// without any dependencies
	helmPackageFile = "../testdata/charts/helmchart-0.1.0.tgz"
	chartName       = "helmchart"
	chartVersion    = "0.1.0"

	// helmPackageV1File contains the path to a Helm package in the v1 format,
	// including dependencies in a requirements.yaml file which should be
	// loaded
	helmPackageV1File = "../testdata/charts/helmchartwithdeps-v1-0.3.0.tgz"
	chartNameV1       = "helmchartwithdeps-v1"
	chartVersionV1    = "0.3.0"

	originalValuesFixture = []byte(`override: original
`)
	chartFilesFixture = []*helmchart.File{
		{
			Name: "values.yaml",
			Data: originalValuesFixture,
		},
	}
	chartFixture = helmchart.Chart{
		Metadata: &helmchart.Metadata{
			Name:    "test",
			Version: "0.1.0",
		},
		Raw:   chartFilesFixture,
		Files: chartFilesFixture,
	}
)

func TestOverwriteChartDefaultValues(t *testing.T) {
	invalidChartFixture := chartFixture
	invalidChartFixture.Raw = []*helmchart.File{}
	invalidChartFixture.Files = []*helmchart.File{}

	testCases := []struct {
		desc      string
		chart     helmchart.Chart
		data      []byte
		ok        bool
		expectErr bool
	}{
		{
			desc:      "invalid chart",
			chart:     invalidChartFixture,
			data:      originalValuesFixture,
			expectErr: true,
		},
		{
			desc:  "identical override",
			chart: chartFixture,
			data:  originalValuesFixture,
		},
		{
			desc:  "valid override",
			chart: chartFixture,
			ok:    true,
			data: []byte(`override: test
`),
		},
		{
			desc:  "empty override",
			chart: chartFixture,
			ok:    true,
			data:  []byte(``),
		},
	}
	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			g := NewWithT(t)

			fixture := tt.chart
			vals, err := chartutil.ReadValues(tt.data)
			g.Expect(err).ToNot(HaveOccurred())
			ok, err := OverwriteChartDefaultValues(&fixture, vals)
			g.Expect(ok).To(Equal(tt.ok))

			if tt.expectErr {
				g.Expect(err).To(HaveOccurred())
				g.Expect(ok).To(Equal(tt.ok))
				return
			}

			if tt.ok {
				for _, f := range fixture.Raw {
					if f.Name == chartutil.ValuesfileName {
						g.Expect(f.Data).To(Equal(tt.data))
					}
				}
				for _, f := range fixture.Files {
					if f.Name == chartutil.ValuesfileName {
						g.Expect(f.Data).To(Equal(tt.data))
					}
				}
			}
		})
	}
}

func TestLoadChartMetadataFromDir(t *testing.T) {
	g := NewWithT(t)

	// Create a chart file that exceeds the max chart file size.
	tmpDir := t.TempDir()
	copy.Copy("../testdata/charts/helmchart", tmpDir)
	bigRequirementsFile := filepath.Join(tmpDir, "requirements.yaml")
	data := make([]byte, helm.MaxChartFileSize+10)
	g.Expect(os.WriteFile(bigRequirementsFile, data, 0o640)).ToNot(HaveOccurred())

	tests := []struct {
		name                string
		dir                 string
		wantName            string
		wantVersion         string
		wantDependencyCount int
		wantErr             string
	}{
		{
			name:        "Loads from dir",
			dir:         "../testdata/charts/helmchart",
			wantName:    "helmchart",
			wantVersion: "0.1.0",
		},
		{
			name:                "Loads from v1 dir including requirements.yaml",
			dir:                 "../testdata/charts/helmchartwithdeps-v1",
			wantName:            chartNameV1,
			wantVersion:         chartVersionV1,
			wantDependencyCount: 1,
		},
		{
			name:    "Error if no Chart.yaml",
			dir:     "../testdata/charts/",
			wantErr: "../testdata/charts/Chart.yaml: no such file or directory",
		},
		{
			name:    "Error if file size exceeds max size",
			dir:     tmpDir,
			wantErr: "size of 'requirements.yaml' exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := LoadChartMetadataFromDir(tt.dir)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).ToNot(BeNil())
			g.Expect(got.Validate()).To(Succeed())
			g.Expect(got.Name).To(Equal(tt.wantName))
			g.Expect(got.Version).To(Equal(tt.wantVersion))
			g.Expect(got.Dependencies).To(HaveLen(tt.wantDependencyCount))
		})
	}
}

func TestLoadChartMetadataFromArchive(t *testing.T) {
	g := NewWithT(t)

	// Create a chart archive that exceeds the max chart size.
	tmpDir := t.TempDir()
	bigArchiveFile := filepath.Join(tmpDir, "chart.tgz")
	data := make([]byte, helm.MaxChartSize+10)
	g.Expect(os.WriteFile(bigArchiveFile, data, 0o640)).ToNot(HaveOccurred())

	tests := []struct {
		name                string
		archive             string
		wantName            string
		wantVersion         string
		wantDependencyCount int
		wantErr             string
	}{
		{
			name:        "Loads from archive",
			archive:     helmPackageFile,
			wantName:    chartName,
			wantVersion: chartVersion,
		},
		{
			name:                "Loads from v1 archive including requirements.yaml",
			archive:             helmPackageV1File,
			wantName:            chartNameV1,
			wantVersion:         chartVersionV1,
			wantDependencyCount: 1,
		},
		{
			name:    "Error on not found",
			archive: "../testdata/invalid.tgz",
			wantErr: "no such file or directory",
		},
		{
			name:    "Error if no Chart.yaml",
			archive: "../testdata/charts/empty.tgz",
			wantErr: "no 'Chart.yaml' found",
		},
		{
			name:    "Error if archive size exceeds max size",
			archive: bigArchiveFile,
			wantErr: "size of chart 'chart.tgz' exceeds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := LoadChartMetadataFromArchive(tt.archive)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).ToNot(BeNil())
			g.Expect(got.Validate()).To(Succeed())
			g.Expect(got.Name).To(Equal(tt.wantName))
			g.Expect(got.Version).To(Equal(tt.wantVersion))
			g.Expect(got.Dependencies).To(HaveLen(tt.wantDependencyCount))
		})
	}
}
