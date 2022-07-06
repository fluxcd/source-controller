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
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/otiai10/copy"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader"
	"github.com/fluxcd/source-controller/internal/helm/repository"
)

func TestLocalBuilder_Build(t *testing.T) {
	g := NewWithT(t)

	// Prepare chart repositories to be used for charts with remote dependency.
	chartB, err := os.ReadFile("./../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartB).ToNot(BeEmpty())
	mockRepo := func() *repository.ChartRepository {
		return &repository.ChartRepository{
			Client: &mockGetter{
				Response: chartB,
			},
			Index: &repo.IndexFile{
				Entries: map[string]repo.ChartVersions{
					"grafana": {
						&repo.ChartVersion{
							Metadata: &helmchart.Metadata{
								Name:    "grafana",
								Version: "6.17.4",
							},
							URLs: []string{"https://example.com/grafana.tgz"},
						},
					},
				},
			},
			RWMutex: &sync.RWMutex{},
		}
	}

	tests := []struct {
		name                string
		reference           Reference
		buildOpts           BuildOptions
		valuesFiles         []helmchart.File
		repositories        map[string]repository.Downloader
		dependentChartPaths []string
		wantValues          chartutil.Values
		wantVersion         string
		wantPackaged        bool
		wantErr             string
	}{
		{
			name:      "invalid reference",
			reference: RemoteReference{},
			wantErr:   "expected local chart reference",
		},
		{
			name:      "invalid local reference - no path",
			reference: LocalReference{},
			wantErr:   "no path set for local chart reference",
		},
		{
			name:      "invalid local reference - no file",
			reference: LocalReference{WorkDir: "/tmp", Path: "non-existent-path.xyz"},
			wantErr:   "no such file or directory",
		},
		{
			name:      "invalid version metadata",
			reference: LocalReference{Path: "../testdata/charts/helmchart"},
			buildOpts: BuildOptions{VersionMetadata: "^"},
			wantErr:   "Invalid Metadata string",
		},
		{
			name:         "with version metadata",
			reference:    LocalReference{Path: "../testdata/charts/helmchart"},
			buildOpts:    BuildOptions{VersionMetadata: "foo"},
			wantVersion:  "0.1.0+foo",
			wantPackaged: true,
		},
		{
			name:         "already packaged chart",
			reference:    LocalReference{Path: "../testdata/charts/helmchart-0.1.0.tgz"},
			wantVersion:  "0.1.0",
			wantPackaged: false,
		},
		{
			name:      "default values",
			reference: LocalReference{Path: "../testdata/charts/helmchart"},
			wantValues: chartutil.Values{
				"replicaCount": float64(1),
			},
			wantVersion:  "0.1.0",
			wantPackaged: true,
		},
		{
			name:      "with values files",
			reference: LocalReference{Path: "../testdata/charts/helmchart"},
			buildOpts: BuildOptions{
				ValuesFiles: []string{"custom-values1.yaml", "custom-values2.yaml"},
			},
			valuesFiles: []helmchart.File{
				{
					Name: "custom-values1.yaml",
					Data: []byte(`replicaCount: 11
nameOverride: "foo-name-override"`),
				},
				{
					Name: "custom-values2.yaml",
					Data: []byte(`replicaCount: 20
fullnameOverride: "full-foo-name-override"`),
				},
			},
			wantValues: chartutil.Values{
				"replicaCount":     float64(20),
				"nameOverride":     "foo-name-override",
				"fullnameOverride": "full-foo-name-override",
			},
			wantVersion:  "0.1.0",
			wantPackaged: true,
		},
		{
			name:      "chart with dependencies",
			reference: LocalReference{Path: "../testdata/charts/helmchartwithdeps"},
			repositories: map[string]repository.Downloader{
				"https://grafana.github.io/helm-charts/": mockRepo(),
			},
			dependentChartPaths: []string{"./../testdata/charts/helmchart"},
			wantVersion:         "0.1.0",
			wantPackaged:        true,
		},
		{
			name:      "v1 chart",
			reference: LocalReference{Path: "./../testdata/charts/helmchart-v1"},
			wantValues: chartutil.Values{
				"replicaCount": float64(1),
			},
			wantVersion:  "0.2.0",
			wantPackaged: true,
		},
		{
			name:      "v1 chart with dependencies",
			reference: LocalReference{Path: "../testdata/charts/helmchartwithdeps-v1"},
			repositories: map[string]repository.Downloader{
				"https://grafana.github.io/helm-charts/": mockRepo(),
			},
			dependentChartPaths: []string{"../testdata/charts/helmchart-v1"},
			wantVersion:         "0.3.0",
			wantPackaged:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			workDir := t.TempDir()

			// Only if the reference is a LocalReference, set the WorkDir.
			localRef, ok := tt.reference.(LocalReference)
			if ok {
				// If the source chart path is valid, copy it into the workdir
				// and update the localRef.Path with the copied local chart
				// path.
				if localRef.Path != "" {
					_, err := os.Lstat(localRef.Path)
					if err == nil {
						helmchartDir := filepath.Join(workDir, "testdata", "charts", filepath.Base(localRef.Path))
						g.Expect(copy.Copy(localRef.Path, helmchartDir)).ToNot(HaveOccurred())
					}
				}
				localRef.WorkDir = workDir
				tt.reference = localRef
			}

			// Write value file in the base dir.
			for _, f := range tt.valuesFiles {
				vPath := filepath.Join(localRef.WorkDir, f.Name)
				g.Expect(os.WriteFile(vPath, f.Data, 0o640)).ToNot(HaveOccurred())
			}

			// Write chart dependencies in the base dir.
			for _, dcp := range tt.dependentChartPaths {
				// Construct the chart path relative to the testdata chart.
				helmchartDir := filepath.Join(workDir, "testdata", "charts", filepath.Base(dcp))
				g.Expect(copy.Copy(dcp, helmchartDir)).ToNot(HaveOccurred())
			}

			// Target path with name similar to the workDir.
			targetPath := workDir + ".tgz"

			dm := NewDependencyManager(
				WithRepositories(tt.repositories),
			)

			b := NewLocalBuilder(dm)
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
			resultChart, err := secureloader.LoadFile(cb.Path)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(resultChart.Metadata.Version).To(Equal(tt.wantVersion))

			for k, v := range tt.wantValues {
				g.Expect(v).To(Equal(resultChart.Values[k]))
			}
		})
	}
}

func TestLocalBuilder_Build_CachedChart(t *testing.T) {
	g := NewWithT(t)

	workDir := t.TempDir()

	testChartPath := "./../testdata/charts/helmchart"

	dm := NewDependencyManager()
	b := NewLocalBuilder(dm)

	tmpDir := t.TempDir()

	// Copy the source chart into the workdir.
	g.Expect(copy.Copy(testChartPath, filepath.Join(workDir, "testdata", "charts", filepath.Base("helmchart")))).ToNot(HaveOccurred())

	reference := LocalReference{WorkDir: workDir, Path: testChartPath}

	// Build first time.
	targetPath := filepath.Join(tmpDir, "chart1.tgz")
	buildOpts := BuildOptions{}
	cb, err := b.Build(context.TODO(), reference, targetPath, buildOpts)
	g.Expect(err).ToNot(HaveOccurred())

	// Set the result as the CachedChart for second build.
	buildOpts.CachedChart = cb.Path

	targetPath2 := filepath.Join(tmpDir, "chart2.tgz")
	cb, err = b.Build(context.TODO(), reference, targetPath2, buildOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cb.Path).To(Equal(targetPath))

	// Rebuild with build option Force.
	buildOpts.Force = true
	cb, err = b.Build(context.TODO(), reference, targetPath2, buildOpts)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cb.Path).To(Equal(targetPath2))
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

			baseDir := t.TempDir()

			for _, f := range tt.files {
				g.Expect(os.WriteFile(filepath.Join(baseDir, f.Name), f.Data, 0o640)).To(Succeed())
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
			in:   "../testdata/local-index.yaml",
		},
		{
			name:    "invalid input file",
			in:      "../testdata/invalid.tgz",
			wantErr: "failed to open file to copy from",
		},
		{
			name:    "invalid input directory",
			in:      "../testdata/charts",
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
