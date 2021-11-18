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
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	helmgetter "helm.sh/helm/v3/pkg/getter"

	"github.com/fluxcd/source-controller/internal/helm/repository"
)

// mockIndexChartGetter returns specific response for index and chart queries.
type mockIndexChartGetter struct {
	IndexResponse []byte
	ChartResponse []byte
	requestedURL  string
}

func (g *mockIndexChartGetter) Get(u string, _ ...helmgetter.Option) (*bytes.Buffer, error) {
	g.requestedURL = u
	r := g.ChartResponse
	if strings.HasSuffix(u, "index.yaml") {
		r = g.IndexResponse
	}
	return bytes.NewBuffer(r), nil
}

func (g *mockIndexChartGetter) LastGet() string {
	return g.requestedURL
}

func TestRemoteBuilder_Build(t *testing.T) {
	g := NewWithT(t)

	chartGrafana, err := os.ReadFile("./../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartGrafana).ToNot(BeEmpty())

	index := []byte(`
apiVersion: v1
entries:
  grafana:
    - urls:
        - https://example.com/grafana.tgz
      description: string
      version: 6.17.4
`)

	mockGetter := &mockIndexChartGetter{
		IndexResponse: index,
		ChartResponse: chartGrafana,
	}

	mockRepo := func() *repository.ChartRepository {
		return &repository.ChartRepository{
			URL:     "https://grafana.github.io/helm-charts/",
			Client:  mockGetter,
			RWMutex: &sync.RWMutex{},
		}
	}

	tests := []struct {
		name         string
		reference    Reference
		buildOpts    BuildOptions
		repository   *repository.ChartRepository
		wantValues   chartutil.Values
		wantVersion  string
		wantPackaged bool
		wantErr      string
	}{
		{
			name:      "invalid reference",
			reference: LocalReference{},
			wantErr:   "expected remote chart reference",
		},
		{
			name:      "invalid reference - no name",
			reference: RemoteReference{},
			wantErr:   "no name set for remote chart reference",
		},
		{
			name:       "chart not in repo",
			reference:  RemoteReference{Name: "foo"},
			repository: mockRepo(),
			wantErr:    "failed to get chart version for remote reference",
		},
		{
			name:       "chart version not in repo",
			reference:  RemoteReference{Name: "grafana", Version: "1.1.1"},
			repository: mockRepo(),
			wantErr:    "failed to get chart version for remote reference",
		},
		{
			name:       "invalid version metadata",
			reference:  RemoteReference{Name: "grafana"},
			repository: mockRepo(),
			buildOpts:  BuildOptions{VersionMetadata: "^"},
			wantErr:    "Invalid Metadata string",
		},
		{
			name:         "with version metadata",
			reference:    RemoteReference{Name: "grafana"},
			repository:   mockRepo(),
			buildOpts:    BuildOptions{VersionMetadata: "foo"},
			wantVersion:  "6.17.4+foo",
			wantPackaged: true,
		},
		{
			name:        "default values",
			reference:   RemoteReference{Name: "grafana"},
			repository:  mockRepo(),
			wantVersion: "0.1.0",
			wantValues: chartutil.Values{
				"replicaCount": float64(1),
			},
		},
		{
			name:      "merge values",
			reference: RemoteReference{Name: "grafana"},
			buildOpts: BuildOptions{
				ValuesFiles: []string{"a.yaml", "b.yaml", "c.yaml"},
			},
			repository:  mockRepo(),
			wantVersion: "6.17.4",
			wantValues: chartutil.Values{
				"a": "b",
				"b": "d",
			},
			wantPackaged: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tmpDir, err := os.MkdirTemp("", "remote-chart-builder-")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(tmpDir)
			targetPath := filepath.Join(tmpDir, "chart.tgz")

			if tt.repository != nil {
				_, err := tt.repository.CacheIndex()
				g.Expect(err).ToNot(HaveOccurred())
				// Cleanup the cache index path.
				defer os.Remove(tt.repository.CachePath)
			}

			b := NewRemoteBuilder(tt.repository)

			cb, err := b.Build(context.TODO(), tt.reference, targetPath, tt.buildOpts)

			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(cb).To(BeZero())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cb.Packaged).To(Equal(tt.wantPackaged), "unexpected Build.Packaged value")
			g.Expect(cb.Path).ToNot(BeEmpty(), "empty Build.Path")

			// Load the resulting chart and verify the values.
			resultChart, err := loader.Load(cb.Path)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(resultChart.Metadata.Version).To(Equal(tt.wantVersion))

			for k, v := range tt.wantValues {
				g.Expect(v).To(Equal(resultChart.Values[k]))
			}
		})
	}
}

func TestRemoteBuilder_Build_CachedChart(t *testing.T) {
	g := NewWithT(t)

	chartGrafana, err := os.ReadFile("./../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartGrafana).ToNot(BeEmpty())

	index := []byte(`
apiVersion: v1
entries:
  helmchart:
    - urls:
        - https://example.com/helmchart-0.1.0.tgz
      description: string
      version: 0.1.0
      name: helmchart
`)

	mockGetter := &mockIndexChartGetter{
		IndexResponse: index,
		ChartResponse: chartGrafana,
	}
	mockRepo := func() *repository.ChartRepository {
		return &repository.ChartRepository{
			URL:     "https://grafana.github.io/helm-charts/",
			Client:  mockGetter,
			RWMutex: &sync.RWMutex{},
		}
	}

	reference := RemoteReference{Name: "helmchart"}
	repository := mockRepo()

	_, err = repository.CacheIndex()
	g.Expect(err).ToNot(HaveOccurred())
	// Cleanup the cache index path.
	defer os.Remove(repository.CachePath)

	b := NewRemoteBuilder(repository)

	tmpDir, err := os.MkdirTemp("", "remote-chart-")
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(tmpDir)

	// Build first time.
	targetPath := filepath.Join(tmpDir, "chart1.tgz")
	defer os.RemoveAll(targetPath)
	buildOpts := BuildOptions{}
	cb, err := b.Build(context.TODO(), reference, targetPath, buildOpts)
	g.Expect(err).ToNot(HaveOccurred())

	// Set the result as the CachedChart for second build.
	buildOpts.CachedChart = cb.Path

	// Rebuild with a new path.
	targetPath2 := filepath.Join(tmpDir, "chart2.tgz")
	defer os.RemoveAll(targetPath2)
	cb, err = b.Build(context.TODO(), reference, targetPath2, buildOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cb.Path).To(Equal(targetPath))

	// Rebuild with build option Force.
	buildOpts.Force = true
	cb, err = b.Build(context.TODO(), reference, targetPath2, buildOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cb.Path).To(Equal(targetPath2))
}

func Test_mergeChartValues(t *testing.T) {
	tests := []struct {
		name    string
		chart   *helmchart.Chart
		paths   []string
		want    map[string]interface{}
		wantErr string
	}{
		{
			name: "merges values",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "a.yaml", Data: []byte("a: b")},
					{Name: "b.yaml", Data: []byte("b: c")},
					{Name: "c.yaml", Data: []byte("b: d")},
				},
			},
			paths: []string{"a.yaml", "b.yaml", "c.yaml"},
			want: map[string]interface{}{
				"a": "b",
				"b": "d",
			},
		},
		{
			name: "uses chart values",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "c.yaml", Data: []byte("b: d")},
				},
				Values: map[string]interface{}{
					"a": "b",
				},
			},
			paths: []string{chartutil.ValuesfileName, "c.yaml"},
			want: map[string]interface{}{
				"a": "b",
				"b": "d",
			},
		},
		{
			name: "unmarshal error",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "invalid", Data: []byte("abcd")},
				},
			},
			paths:   []string{"invalid"},
			wantErr: "unmarshaling values from 'invalid' failed",
		},
		{
			name:    "error on invalid path",
			chart:   &helmchart.Chart{},
			paths:   []string{"a.yaml"},
			wantErr: "no values file found at path 'a.yaml'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := mergeChartValues(tt.chart, tt.paths)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func Test_validatePackageAndWriteToPath(t *testing.T) {
	g := NewWithT(t)

	tmpDir, err := os.MkdirTemp("", "validate-pkg-chart-")
	g.Expect(err).ToNot(HaveOccurred())
	defer os.RemoveAll(tmpDir)

	validF, err := os.Open("./../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	defer validF.Close()

	chartPath := filepath.Join(tmpDir, "chart.tgz")
	defer os.Remove(chartPath)
	err = validatePackageAndWriteToPath(validF, chartPath)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartPath).To(BeARegularFile())

	emptyF, err := os.Open("./../testdata/charts/empty.tgz")
	defer emptyF.Close()
	g.Expect(err).ToNot(HaveOccurred())
	err = validatePackageAndWriteToPath(emptyF, filepath.Join(tmpDir, "out.tgz"))
	g.Expect(err).To(HaveOccurred())
}

func Test_pathIsDir(t *testing.T) {
	tests := []struct {
		name string
		p    string
		want bool
	}{
		{name: "directory", p: "../testdata/", want: true},
		{name: "file", p: "../testdata/local-index.yaml", want: false},
		{name: "not found error", p: "../testdata/does-not-exist.yaml", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(pathIsDir(tt.p)).To(Equal(tt.want))
		})
	}
}
