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

package chart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	. "github.com/onsi/gomega"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader"
	"github.com/fluxcd/source-controller/internal/helm/repository"
)

type mockTagsGetter struct {
	tags map[string][]string
}

func (m *mockTagsGetter) Tags(requestURL string) ([]string, error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return nil, err
	}

	name := filepath.Base(u.Path)
	if tags, ok := m.tags[name]; ok {
		return tags, nil
	}
	return nil, fmt.Errorf("no tags found for %s with requestURL %s", name, requestURL)
}

func (m *mockTagsGetter) Login(_ string, _ ...registry.LoginOption) error {
	return nil
}

func (m *mockTagsGetter) Logout(_ string, _ ...registry.LogoutOption) error {
	return nil
}

// mockGetter is a simple mocking getter.Getter implementation, returning
// a byte response to any provided URL.
type mockGetter struct {
	Response []byte
}

func (g *mockGetter) Get(_ string, _ ...helmgetter.Option) (*bytes.Buffer, error) {
	r := g.Response
	return bytes.NewBuffer(r), nil
}

func TestDependencyManager_Clear(t *testing.T) {
	g := NewWithT(t)

	file, err := os.CreateTemp("", "")
	g.Expect(err).ToNot(HaveOccurred())
	ociRepoWithCreds, err := repository.NewOCIChartRepository("oci://example.com", repository.WithCredentialsFile(file.Name()))
	g.Expect(err).ToNot(HaveOccurred())

	downloaders := map[string]repository.Downloader{
		"with index": &repository.ChartRepository{
			Index:   repo.NewIndexFile(),
			RWMutex: &sync.RWMutex{},
		},
		"cached cache path": &repository.ChartRepository{
			CachePath: "/invalid/path/resets",
			Cached:    true,
			RWMutex:   &sync.RWMutex{},
		},
		"with credentials":    ociRepoWithCreds,
		"without credentials": &repository.OCIChartRepository{},
		"nil downloader":      nil,
	}

	dm := NewDependencyManager(WithRepositories(downloaders))
	g.Expect(dm.Clear()).To(BeNil())
	g.Expect(dm.downloaders).To(HaveLen(len(downloaders)))
	for _, v := range downloaders {
		switch v := v.(type) {
		case *repository.ChartRepository:
			g.Expect(v.Index).To(BeNil())
			g.Expect(v.CachePath).To(BeEmpty())
			g.Expect(v.Cached).To(BeFalse())
		case *repository.OCIChartRepository:
			g.Expect(v.HasCredentials()).To(BeFalse())
		}
	}

	if _, err := os.Stat(file.Name()); !errors.Is(err, os.ErrNotExist) {
		err = os.Remove(file.Name())
		g.Expect(err).ToNot(HaveOccurred())
	}
}

func TestDependencyManager_Build(t *testing.T) {
	g := NewWithT(t)

	// Mock chart used as grafana chart in the test below. The cached repository
	// takes care of the actual grafana related details in the chart index.
	chartGrafana, err := os.ReadFile("./../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartGrafana).ToNot(BeEmpty())

	mockrepos := []repository.Downloader{
		&repository.OCIChartRepository{
			URL: url.URL{
				Scheme: "oci",
				Host:   "example.com",
			},
			Client: &mockGetter{
				Response: chartGrafana,
			},
			RegistryClient: &mockTagsGetter{
				tags: map[string][]string{
					"grafana": {"6.17.4"},
				},
			},
		},
		&repository.ChartRepository{
			Client: &mockGetter{
				Response: chartGrafana,
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
		},
	}

	for _, repo := range mockrepos {
		build(t, repo)
	}
}

func build(t *testing.T, mockRepo repository.Downloader) {
	tests := []struct {
		name                       string
		baseDir                    string
		path                       string
		downloaders                map[string]repository.Downloader
		getChartDownloaderCallback GetChartDownloaderCallback
		want                       int
		wantChartFunc              func(g *WithT, c *helmchart.Chart)
		wantErr                    string
	}{
		{
			name:    "build failure returns error",
			baseDir: "./../testdata/charts",
			path:    "helmchartwithdeps",
			wantErr: "failed to add remote dependency 'grafana': no chart repository for URL",
		},
		{
			name:    "no dependencies returns zero",
			baseDir: "./../testdata/charts",
			path:    "helmchart",
			wantChartFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(0))
			},
			want: 0,
		},
		{
			name:    "no dependency returns zero - v1",
			baseDir: "./../testdata/charts",
			path:    "helmchart-v1",
			wantChartFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(0))
			},
			want: 0,
		},
		{
			name:    "build with dependencies using lock file",
			baseDir: "./../testdata/charts",
			path:    "helmchartwithdeps",
			downloaders: map[string]repository.Downloader{
				"https://grafana.github.io/helm-charts/": mockRepo,
			},
			getChartDownloaderCallback: func(url string) (repository.Downloader, error) {
				return &repository.ChartRepository{URL: "https://grafana.github.io/helm-charts/"}, nil
			},
			wantChartFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(2))
				g.Expect(c.Lock.Dependencies).To(HaveLen(3))
			},
			want: 2,
		},
		{
			name:    "build with dependencies - v1",
			baseDir: "./../testdata/charts",
			path:    "helmchartwithdeps-v1",
			wantChartFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(1))
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			chart, err := secureloader.Load(tt.baseDir, tt.path)
			g.Expect(err).ToNot(HaveOccurred())

			dm := NewDependencyManager(
				WithRepositories(tt.downloaders),
				WithDownloaderCallback(tt.getChartDownloaderCallback),
			)
			absBaseDir, err := filepath.Abs(tt.baseDir)
			g.Expect(err).ToNot(HaveOccurred())
			got, err := dm.Build(context.TODO(), LocalReference{WorkDir: absBaseDir, Path: tt.path}, chart)

			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeZero())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
			if tt.wantChartFunc != nil {
				tt.wantChartFunc(g, chart)
			}
		})
	}
}

func TestDependencyManager_build(t *testing.T) {
	tests := []struct {
		name    string
		deps    map[string]*helmchart.Dependency
		wantErr string
	}{
		{
			name: "error remote dependency",
			deps: map[string]*helmchart.Dependency{
				"example": {Repository: "https://example.com"},
			},
			wantErr: "failed to add remote dependency",
		},
		{
			name: "error local dependency",
			deps: map[string]*helmchart.Dependency{
				"example": {Repository: "file:///invalid"},
			},
			wantErr: "failed to add remote dependency",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			dm := NewDependencyManager()
			err := dm.build(context.TODO(), LocalReference{}, &helmchart.Chart{}, tt.deps)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestDependencyManager_addLocalDependency(t *testing.T) {
	tests := []struct {
		name     string
		dep      *helmchart.Dependency
		wantErr  string
		wantFunc func(g *WithT, c *helmchart.Chart)
	}{
		{
			name: "local dependency",
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "file://../helmchart",
			},
			wantFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(1))
			},
		},
		{
			name: "version not matching constraint",
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    "0.2.0",
				Repository: "file://../helmchart",
			},
			wantErr: "can't get a valid version for constraint '0.2.0'",
		},
		{
			name: "invalid local reference",
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "file://../../../absolutely/invalid",
			},
			wantErr: "no chart found at '/absolutely/invalid'",
		},
		{
			name: "invalid chart archive",
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "file://../empty.tgz",
			},
			wantErr: "failed to load chart from '/empty.tgz'",
		},
		{
			name: "invalid constraint",
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    "invalid",
				Repository: "file://../helmchart",
			},
			wantErr: "invalid version/constraint format 'invalid'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			dm := NewDependencyManager()
			chart := &helmchart.Chart{}

			absWorkDir, err := filepath.Abs("../testdata/charts")
			g.Expect(err).ToNot(HaveOccurred())

			err = dm.addLocalDependency(LocalReference{WorkDir: absWorkDir, Path: "helmchartwithdeps"},
				&chartWithLock{Chart: chart}, tt.dep)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())

			if tt.wantFunc != nil {
				tt.wantFunc(g, chart)
			}
		})
	}
}

func TestDependencyManager_addRemoteDependency(t *testing.T) {
	g := NewWithT(t)

	chartB, err := os.ReadFile("../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartB).ToNot(BeEmpty())

	tests := []struct {
		name        string
		downloaders map[string]repository.Downloader
		dep         *helmchart.Dependency
		wantFunc    func(g *WithT, c *helmchart.Chart)
		wantErr     string
	}{
		{
			name: "adds remote dependency",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{
					Client: &mockGetter{
						Response: chartB,
					},
					Index: &repo.IndexFile{
						Entries: map[string]repo.ChartVersions{
							chartName: {
								&repo.ChartVersion{
									Metadata: &helmchart.Metadata{
										Name:    chartName,
										Version: chartVersion,
									},
									URLs: []string{"https://example.com/foo.tgz"},
								},
							},
						},
					},
					RWMutex: &sync.RWMutex{},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Repository: "https://example.com",
			},
			wantFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(1))
			},
		},
		{
			name:        "resolve repository error",
			downloaders: map[string]repository.Downloader{},
			dep: &helmchart.Dependency{
				Repository: "https://example.com",
			},
			wantErr: "no chart repository for URL",
		},
		{
			name:        "resolve aliased repository error",
			downloaders: map[string]repository.Downloader{},
			dep: &helmchart.Dependency{
				Repository: "@fantastic-charts",
			},
			wantErr: "aliased repository dependency is not supported",
		},
		{
			name: "strategic load error",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{
					CachePath: "/invalid/cache/path/foo",
					RWMutex:   &sync.RWMutex{},
				},
			},
			dep: &helmchart.Dependency{
				Repository: "https://example.com",
			},
			wantErr: "failed to strategically load index",
		},
		{
			name: "repository get error",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{
					Index:   &repo.IndexFile{},
					RWMutex: &sync.RWMutex{},
				},
			},
			dep: &helmchart.Dependency{
				Repository: "https://example.com",
			},
			wantErr: "no chart name found",
		},
		{
			name: "repository version constraint error",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{
					Index: &repo.IndexFile{
						Entries: map[string]repo.ChartVersions{
							chartName: {
								&repo.ChartVersion{
									Metadata: &helmchart.Metadata{
										Name:    chartName,
										Version: "0.1.0",
									},
								},
							},
						},
					},
					RWMutex: &sync.RWMutex{},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    "0.2.0",
				Repository: "https://example.com",
			},
			wantErr: fmt.Sprintf("no '%s' chart with version matching '0.2.0' found", chartName),
		},
		{
			name: "repository chart download error",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{
					Index: &repo.IndexFile{
						Entries: map[string]repo.ChartVersions{
							chartName: {
								&repo.ChartVersion{
									Metadata: &helmchart.Metadata{
										Name:    chartName,
										Version: chartVersion,
									},
								},
							},
						},
					},
					RWMutex: &sync.RWMutex{},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "https://example.com",
			},
			wantErr: "chart download of version '0.1.0' failed",
		},
		{
			name: "chart load error",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{
					Client: &mockGetter{},
					Index: &repo.IndexFile{
						Entries: map[string]repo.ChartVersions{
							chartName: {
								&repo.ChartVersion{
									Metadata: &helmchart.Metadata{
										Name:    chartName,
										Version: chartVersion,
									},
									URLs: []string{"https://example.com/foo.tgz"},
								},
							},
						},
					},
					RWMutex: &sync.RWMutex{},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "https://example.com",
			},
			wantErr: "failed to load downloaded archive of version '0.1.0'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			dm := &DependencyManager{
				downloaders: tt.downloaders,
			}
			chart := &helmchart.Chart{}
			err := dm.addRemoteDependency(&chartWithLock{Chart: chart}, tt.dep)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			if tt.wantFunc != nil {
				tt.wantFunc(g, chart)
			}
		})
	}
}

func TestDependencyManager_addRemoteOCIDependency(t *testing.T) {
	g := NewWithT(t)

	chartB, err := os.ReadFile("../testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chartB).ToNot(BeEmpty())

	tests := []struct {
		name        string
		downloaders map[string]repository.Downloader
		dep         *helmchart.Dependency
		wantFunc    func(g *WithT, c *helmchart.Chart)
		wantErr     string
	}{
		{
			name: "adds remote oci dependency",
			downloaders: map[string]repository.Downloader{
				"oci://example.com": &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com",
					},
					Client: &mockGetter{
						Response: chartB,
					},
					RegistryClient: &mockTagsGetter{
						tags: map[string][]string{
							"helmchart": {"0.1.0"},
						},
					},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Repository: "oci://example.com",
			},
			wantFunc: func(g *WithT, c *helmchart.Chart) {
				g.Expect(c.Dependencies()).To(HaveLen(1))
				dep := c.Dependencies()[0]
				g.Expect(dep).NotTo(BeNil())
			},
		},
		{
			name: "remote oci repository fetch tags error",
			downloaders: map[string]repository.Downloader{
				"oci://example.com": &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com",
					},
					RegistryClient: &mockTagsGetter{
						tags: map[string][]string{},
					},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Repository: "oci://example.com",
			},
			wantErr: fmt.Sprintf("no tags found for %s", chartName),
		},
		{
			name: "remote oci repository version constraint error",
			downloaders: map[string]repository.Downloader{
				"oci://example.com": &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com",
					},
					Client: &mockGetter{},
					RegistryClient: &mockTagsGetter{
						tags: map[string][]string{
							"helmchart": {"0.1.0"},
						},
					},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    "0.2.0",
				Repository: "oci://example.com",
			},
			wantErr: "failed to load downloaded archive of version '0.2.0'",
		},
		{
			name: "chart load error",
			downloaders: map[string]repository.Downloader{
				"oci://example.com": &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com",
					},
					Client: &mockGetter{},
					RegistryClient: &mockTagsGetter{
						tags: map[string][]string{
							"helmchart": {"0.1.0"},
						},
					},
				},
			},
			dep: &helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "oci://example.com",
			},
			wantErr: "failed to load downloaded archive of version '0.1.0'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			dm := &DependencyManager{
				downloaders: tt.downloaders,
			}
			chart := &helmchart.Chart{}
			err := dm.addRemoteDependency(&chartWithLock{Chart: chart}, tt.dep)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			if tt.wantFunc != nil {
				tt.wantFunc(g, chart)
			}
		})
	}
}

func TestDependencyManager_resolveRepository(t *testing.T) {
	tests := []struct {
		name                       string
		downloaders                map[string]repository.Downloader
		getChartDownloaderCallback GetChartDownloaderCallback
		url                        string
		want                       repository.Downloader
		wantDownloaders            map[string]repository.Downloader
		wantErr                    string
	}{
		{
			name: "resolves from downloaders index",
			url:  "https://example.com",
			downloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{URL: "https://example.com"},
			},
			want: &repository.ChartRepository{URL: "https://example.com"},
		},
		{
			name: "resolves from callback",
			url:  "https://example.com",
			getChartDownloaderCallback: func(_ string) (repository.Downloader, error) {
				return &repository.ChartRepository{URL: "https://example.com"}, nil
			},
			want: &repository.ChartRepository{URL: "https://example.com"},
			wantDownloaders: map[string]repository.Downloader{
				"https://example.com/": &repository.ChartRepository{URL: "https://example.com"},
			},
		},
		{
			name: "error from callback",
			url:  "https://example.com",
			getChartDownloaderCallback: func(_ string) (repository.Downloader, error) {
				return nil, errors.New("a very unique error")
			},
			wantErr:         "a very unique error",
			wantDownloaders: map[string]repository.Downloader{},
		},
		{
			name:    "error on not found",
			url:     "https://example.com",
			wantErr: "no chart repository for URL",
		},
		{
			name: "resolves from oci repository",
			url:  "oci://example.com",
			downloaders: map[string]repository.Downloader{
				"oci://example.com": &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com",
					},
				},
			},
			want: &repository.OCIChartRepository{
				URL: url.URL{
					Scheme: "oci",
					Host:   "example.com",
				},
			},
		},
		{
			name: "resolves oci repository from callback",
			url:  "oci://example.com",
			getChartDownloaderCallback: func(_ string) (repository.Downloader, error) {
				return &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com"},
				}, nil
			},
			want: &repository.OCIChartRepository{
				URL: url.URL{
					Scheme: "oci",
					Host:   "example.com",
				},
			},

			wantDownloaders: map[string]repository.Downloader{
				"oci://example.com": &repository.OCIChartRepository{
					URL: url.URL{
						Scheme: "oci",
						Host:   "example.com",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			dm := &DependencyManager{
				downloaders:                tt.downloaders,
				getChartDownloaderCallback: tt.getChartDownloaderCallback,
			}

			got, err := dm.resolveRepository(tt.url)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
			if tt.wantDownloaders != nil {
				g.Expect(dm.downloaders).To(Equal(tt.wantDownloaders))
			}
		})
	}
}

func TestDependencyManager_secureLocalChartPath(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
		path    string
		dep     *helmchart.Dependency
		want    string
		wantErr string
	}{
		{
			name:    "secure local file path",
			baseDir: "/tmp/workdir",
			path:    "/chart",
			dep: &helmchart.Dependency{
				Repository: "../dep",
			},
			want: "/tmp/workdir/dep",
		},
		{
			name:    "insecure local file path",
			baseDir: "/tmp/workdir",
			path:    "/",
			dep: &helmchart.Dependency{
				Repository: "/../../dep",
			},
			want: "/tmp/workdir/dep",
		},
		{
			name: "URL parse error",
			dep: &helmchart.Dependency{
				Repository: ": //example.com",
			},
			wantErr: "missing protocol scheme",
		},
		{
			name: "error on URL scheme other than file",
			dep: &helmchart.Dependency{
				Repository: "https://example.com",
			},
			wantErr: "not a local chart reference",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			dm := NewDependencyManager()
			got, err := dm.secureLocalChartPath(LocalReference{WorkDir: tt.baseDir, Path: tt.path}, tt.dep)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).ToNot(BeEmpty())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func Test_collectMissing(t *testing.T) {
	tests := []struct {
		name    string
		current []*helmchart.Chart
		reqs    []*helmchart.Dependency
		want    map[string]*helmchart.Dependency
	}{
		{
			name:    "one missing",
			current: []*helmchart.Chart{},
			reqs: []*helmchart.Dependency{
				{Name: chartName},
			},
			want: map[string]*helmchart.Dependency{
				chartName: {Name: chartName},
			},
		},
		{
			name: "alias missing",
			current: []*helmchart.Chart{
				{
					Metadata: &helmchart.Metadata{
						Name: chartName,
					},
				},
			},
			reqs: []*helmchart.Dependency{
				{Name: chartName},
				{Name: chartName, Alias: chartName + "-alias"},
			},
			want: map[string]*helmchart.Dependency{
				chartName + "-alias": {Name: chartName, Alias: chartName + "-alias"},
			},
		},
		{
			name: "all current",
			current: []*helmchart.Chart{
				{
					Metadata: &helmchart.Metadata{
						Name: chartName,
					},
				},
			},
			reqs: []*helmchart.Dependency{
				{Name: chartName},
			},
			want: nil,
		},
		{
			name:    "nil",
			current: nil,
			reqs:    nil,
			want:    nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run(tt.name, func(t *testing.T) {
				g := NewWithT(t)
				g.Expect(collectMissing(tt.current, tt.reqs)).To(Equal(tt.want))
			})
		})
	}
}

func Test_isLocalDep(t *testing.T) {
	tests := []struct {
		name string
		dep  *helmchart.Dependency
		want bool
	}{
		{
			name: "file protocol",
			dep:  &helmchart.Dependency{Repository: "file:///some/path"},
			want: true,
		},
		{
			name: "empty",
			dep:  &helmchart.Dependency{Repository: ""},
			want: true,
		},
		{
			name: "https url",
			dep:  &helmchart.Dependency{Repository: "https://example.com"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(isLocalDep(tt.dep)).To(Equal(tt.want))
		})
	}
}
