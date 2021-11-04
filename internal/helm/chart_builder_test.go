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

package helm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/repo"
)

func TestChartBuildResult_String(t *testing.T) {
	g := NewWithT(t)

	var result *ChartBuildResult
	g.Expect(result.String()).To(Equal(""))
	result = &ChartBuildResult{}
	g.Expect(result.String()).To(Equal(""))
	result = &ChartBuildResult{Path: "/foo/"}
	g.Expect(result.String()).To(Equal("/foo/"))
}

func TestChartBuilder_Build(t *testing.T) {
	tests := []struct {
		name                       string
		baseDir                    string
		path                       string
		valueFiles                 []string
		repositories               map[string]*ChartRepository
		getChartRepositoryCallback GetChartRepositoryCallback
		wantErr                    string
	}{
		{
			name: "builds chart from directory",
			path: "testdata/charts/helmchart",
		},
		{
			name: "builds chart from package",
			path: "testdata/charts/helmchart-0.1.0.tgz",
		},
		{
			// TODO(hidde): add more diverse tests
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			b, err := NewChartBuilder(tt.path)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(b).ToNot(BeNil())

			b.WithBaseDir(tt.baseDir)
			b.WithValueFiles(tt.valueFiles...)
			b.WithChartRepositoryCallback(b.getChartRepositoryCallback)
			for k, v := range tt.repositories {
				b.WithChartRepository(k, v)
			}

			out := tmpFile("build-0.1.0", ".tgz")
			defer os.RemoveAll(out)
			got, err := b.Build(context.TODO(), out)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).ToNot(BeNil())

			g.Expect(got.Path).ToNot(BeEmpty())
			g.Expect(got.Path).To(Equal(out))
			g.Expect(got.Path).To(BeARegularFile())
			_, err = loader.Load(got.Path)
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestChartBuilder_load(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		chart    *helmchart.Chart
		wantFunc func(g *WithT, c *helmchart.Chart)
		wantErr  string
	}{
		{
			name:  "loads chart",
			chart: nil,
			path:  "testdata/charts/helmchart-0.1.0.tgz",
			wantFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Metadata.Name).To(Equal("helmchart"))
				g.Expect(c.Files).ToNot(BeZero())
			},
		},
		{
			name: "overwrites chart without any files (metadata shim)",
			chart: &helmchart.Chart{
				Metadata: &helmchart.Metadata{Name: "dummy"},
			},
			path: "testdata/charts/helmchart-0.1.0.tgz",
			wantFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Metadata.Name).To(Equal("helmchart"))
				g.Expect(c.Files).ToNot(BeZero())
			},
		},
		{
			name: "does not overwrite loaded chart",
			chart: &helmchart.Chart{
				Metadata: &helmchart.Metadata{Name: "dummy"},
				Files: []*helmchart.File{
					{Name: "mock.yaml", Data: []byte("loaded chart")},
				},
			},
			path: "testdata/charts/helmchart-0.1.0.tgz",
			wantFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Metadata.Name).To(Equal("dummy"))
				g.Expect(c.Files).To(HaveLen(1))
			},
		},
		{
			name:    "no path",
			wantErr: "failed to load chart: path not set",
		},
		{
			name:    "invalid chart",
			path:    "testdata/charts/empty.tgz",
			wantErr: "failed to load chart: no files in chart archive",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			b := &ChartBuilder{
				path:  tt.path,
				chart: tt.chart,
			}
			err := b.load()
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			if tt.wantFunc != nil {
				tt.wantFunc(g, b.chart)
			}
		})
	}
}

func TestChartBuilder_buildDependencies(t *testing.T) {
	g := NewWithT(t)

	chartB, err := os.ReadFile("testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartB).ToNot(BeEmpty())

	mockRepo := func() *ChartRepository {
		return &ChartRepository{
			Client: &mockGetter{
				response: chartB,
			},
			Index: &repo.IndexFile{
				Entries: map[string]repo.ChartVersions{
					"grafana": {
						&repo.ChartVersion{
							Metadata: &helmchart.Metadata{
								Name:    "grafana",
								Version: "6.17.4",
							},
							URLs: []string{"https://example.com/chart.tgz"},
						},
					},
				},
			},
			RWMutex: &sync.RWMutex{},
		}
	}

	var mockCallback GetChartRepositoryCallback = func(url string) (*ChartRepository, error) {
		if url == "https://grafana.github.io/helm-charts/" {
			return mockRepo(), nil
		}
		return nil, fmt.Errorf("no repository for URL")
	}

	tests := []struct {
		name                       string
		baseDir                    string
		path                       string
		chart                      *helmchart.Chart
		fromDir                    bool
		repositories               map[string]*ChartRepository
		getChartRepositoryCallback GetChartRepositoryCallback
		wantCollectedDependencies  int
		wantErr                    string
	}{
		{
			name:                       "builds dependencies using callback",
			fromDir:                    true,
			baseDir:                    "testdata/charts",
			path:                       "testdata/charts/helmchartwithdeps",
			getChartRepositoryCallback: mockCallback,
			wantCollectedDependencies:  2,
		},
		{
			name:    "builds dependencies using repositories",
			fromDir: true,
			baseDir: "testdata/charts",
			path:    "testdata/charts/helmchartwithdeps",
			repositories: map[string]*ChartRepository{
				"https://grafana.github.io/helm-charts/": mockRepo(),
			},
			wantCollectedDependencies: 2,
		},
		{
			name: "skips dependency build for packaged chart",
			path: "testdata/charts/helmchart-0.1.0.tgz",
		},
		{
			name:    "attempts to load chart",
			fromDir: true,
			path:    "testdata",
			wantErr: "failed to ensure chart has no missing dependencies",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			b := &ChartBuilder{
				baseDir:                    tt.baseDir,
				path:                       tt.path,
				chart:                      tt.chart,
				repositories:               tt.repositories,
				getChartRepositoryCallback: tt.getChartRepositoryCallback,
			}

			result := &ChartBuildResult{SourceIsDir: tt.fromDir}
			err := b.buildDependencies(context.TODO(), result)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(result.CollectedDependencies).To(BeZero())
				g.Expect(b.chart).To(Equal(tt.chart))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(result).ToNot(BeNil())
			g.Expect(result.CollectedDependencies).To(Equal(tt.wantCollectedDependencies))
			if tt.wantCollectedDependencies > 0 {
				g.Expect(b.chart).ToNot(Equal(tt.chart))
			}
		})
	}
}

func TestChartBuilder_mergeValues(t *testing.T) {
	tests := []struct {
		name       string
		baseDir    string
		path       string
		isDir      bool
		chart      *helmchart.Chart
		valueFiles []string
		want       map[string]interface{}
		wantErr    string
	}{
		{
			name: "merges chart values",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "a.yaml", Data: []byte("a: b")},
					{Name: "b.yaml", Data: []byte("a: c")},
				},
			},
			valueFiles: []string{"a.yaml", "b.yaml"},
			want: map[string]interface{}{
				"a": "c",
			},
		},
		{
			name: "chart values merge error",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "b.yaml", Data: []byte("a: c")},
				},
			},
			valueFiles: []string{"a.yaml"},
			wantErr:    "failed to merge chart values",
		},
		{
			name:       "merges file values",
			isDir:      true,
			baseDir:    "testdata/charts",
			path:       "helmchart",
			valueFiles: []string{"helmchart/values-prod.yaml"},
			want: map[string]interface{}{
				"replicaCount": float64(2),
			},
		},
		{
			name:       "file values merge error",
			isDir:      true,
			baseDir:    "testdata/charts",
			path:       "helmchart",
			valueFiles: []string{"invalid.yaml"},
			wantErr:    "failed to merge value files",
		},
		{
			name:    "error on chart load failure",
			baseDir: "testdata/charts",
			path:    "invalid",
			wantErr: "failed to load chart",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			b := &ChartBuilder{
				baseDir:    tt.baseDir,
				path:       tt.path,
				chart:      tt.chart,
				valueFiles: tt.valueFiles,
			}

			result := &ChartBuildResult{SourceIsDir: tt.isDir}
			err := b.mergeValues(result)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(result.ValuesOverwrite).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(result.ValuesOverwrite).To(Equal(tt.want))
		})
	}
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

func Test_mergeFileValues(t *testing.T) {
	tests := []struct {
		name    string
		files   []*helmchart.File
		paths   []string
		want    map[string]interface{}
		wantErr string
	}{
		{
			name: "merges values from files",
			files: []*helmchart.File{
				{Name: "a.yaml", Data: []byte("a: b")},
				{Name: "b.yaml", Data: []byte("b: c")},
				{Name: "c.yaml", Data: []byte("b: d")},
			},
			paths: []string{"a.yaml", "b.yaml", "c.yaml"},
			want: map[string]interface{}{
				"a": "b",
				"b": "d",
			},
		},
		{
			name:    "illegal traverse",
			paths:   []string{"../../../traversing/illegally/a/p/a/b"},
			wantErr: "no values file found at path '/traversing/illegally/a/p/a/b'",
		},
		{
			name: "unmarshal error",
			files: []*helmchart.File{
				{Name: "invalid", Data: []byte("abcd")},
			},
			paths:   []string{"invalid"},
			wantErr: "unmarshaling values from 'invalid' failed",
		},
		{
			name:    "error on invalid path",
			paths:   []string{"a.yaml"},
			wantErr: "no values file found at path '/a.yaml'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			baseDir, err := os.MkdirTemp("", "merge-file-values-*")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(baseDir)

			for _, f := range tt.files {
				g.Expect(os.WriteFile(filepath.Join(baseDir, f.Name), f.Data, 0644)).To(Succeed())
			}

			got, err := mergeFileValues(baseDir, tt.paths)
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

func Test_copyFileToPath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{
			name: "copies input file",
			in:   "testdata/local-index.yaml",
		},
		{
			name:    "invalid input file",
			in:      "testdata/invalid.tgz",
			wantErr: "failed to open file to copy from",
		},
		{
			name:    "invalid input directory",
			in:      "testdata/charts",
			wantErr: "failed to read from source during copy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			out := tmpFile("copy-0.1.0", ".tgz")
			defer os.RemoveAll(out)
			err := copyFileToPath(tt.in, out)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out).To(BeARegularFile())
			f1, err := os.ReadFile(tt.in)
			g.Expect(err).ToNot(HaveOccurred())
			f2, err := os.ReadFile(out)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(f2).To(Equal(f1))
		})
	}
}

func Test_packageToPath(t *testing.T) {
	g := NewWithT(t)

	chart, err := loader.Load("testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chart).ToNot(BeNil())

	out := tmpFile("chart-0.1.0", ".tgz")
	defer os.RemoveAll(out)
	err = packageToPath(chart, out)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(out).To(BeARegularFile())
	_, err = loader.Load(out)
	g.Expect(err).ToNot(HaveOccurred())
}

func Test_pathIsDir(t *testing.T) {
	tests := []struct {
		name string
		p    string
		want bool
	}{
		{name: "directory", p: "testdata/", want: true},
		{name: "file", p: "testdata/local-index.yaml", want: false},
		{name: "not found error", p: "testdata/does-not-exist.yaml", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(pathIsDir(tt.p)).To(Equal(tt.want))
		})
	}
}

func tmpFile(prefix, suffix string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), prefix+hex.EncodeToString(randBytes)+suffix)
}
