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

package repository

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fluxcd/source-controller/internal/cache"
	"github.com/fluxcd/source-controller/internal/helm"
	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
)

var now = time.Now()

const (
	testFile            = "../testdata/local-index.yaml"
	chartmuseumTestFile = "../testdata/chartmuseum-index.yaml"
	unorderedTestFile   = "../testdata/local-index-unordered.yaml"
)

// mockGetter is a simple mocking getter.Getter implementation, returning
// a byte response to any provided URL.
type mockGetter struct {
	Response      []byte
	LastCalledURL string
}

func (g *mockGetter) Get(u string, _ ...helmgetter.Option) (*bytes.Buffer, error) {
	r := g.Response
	g.LastCalledURL = u
	return bytes.NewBuffer(r), nil
}

func TestNewChartRepository(t *testing.T) {
	repositoryURL := "https://example.com"
	providers := helmgetter.Providers{
		helmgetter.Provider{
			Schemes: []string{"https"},
			New:     helmgetter.NewHTTPGetter,
		},
	}
	options := []helmgetter.Option{helmgetter.WithBasicAuth("username", "password")}

	t.Run("should construct chart repository", func(t *testing.T) {
		g := NewWithT(t)

		r, err := NewChartRepository(repositoryURL, "", providers, nil, options)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r).ToNot(BeNil())
		g.Expect(r.URL).To(Equal(repositoryURL))
		g.Expect(r.Client).ToNot(BeNil())
		g.Expect(r.Options).To(Equal(options))
	})

	t.Run("should error on URL parsing failure", func(t *testing.T) {
		g := NewWithT(t)
		r, err := NewChartRepository("https://ex ample.com", "", nil, nil, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err).To(BeAssignableToTypeOf(&url.Error{}))
		g.Expect(r).To(BeNil())

	})

	t.Run("should error on unsupported scheme", func(t *testing.T) {
		g := NewWithT(t)

		r, err := NewChartRepository("http://example.com", "", providers, nil, nil)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(Equal("scheme \"http\" not supported"))
		g.Expect(r).To(BeNil())
	})
}

func TestChartRepository_Get(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	r.Index = repo.NewIndexFile()
	charts := []struct {
		name    string
		version string
		url     string
		digest  string
		created time.Time
	}{
		{name: "chart", version: "0.0.1", url: "http://example.com/charts", digest: "sha256:1234567890"},
		{name: "chart", version: "0.1.0", url: "http://example.com/charts", digest: "sha256:1234567890abc"},
		{name: "chart", version: "0.1.1", url: "http://example.com/charts", digest: "sha256:1234567890abc"},
		{name: "chart", version: "0.1.5+b.min.minute", url: "http://example.com/charts", digest: "sha256:1234567890abc", created: now.Add(-time.Minute)},
		{name: "chart", version: "0.1.5+a.min.hour", url: "http://example.com/charts", digest: "sha256:1234567890abc", created: now.Add(-time.Hour)},
		{name: "chart", version: "0.1.5+c.now", url: "http://example.com/charts", digest: "sha256:1234567890abc", created: now},
		{name: "chart", version: "0.2.0", url: "http://example.com/charts", digest: "sha256:1234567890abc"},
		{name: "chart", version: "1.0.0", url: "http://example.com/charts", digest: "sha256:1234567890abc"},
		{name: "chart", version: "1.1.0-rc.1", url: "http://example.com/charts", digest: "sha256:1234567890abc"},
	}
	for _, c := range charts {
		g.Expect(r.Index.MustAdd(
			&chart.Metadata{Name: c.name, Version: c.version},
			fmt.Sprintf("%s-%s.tgz", c.name, c.version), c.url, c.digest),
		).To(Succeed())
		if !c.created.IsZero() {
			r.Index.Entries["chart"][len(r.Index.Entries["chart"])-1].Created = c.created
		}
	}
	r.Index.SortEntries()

	tests := []struct {
		name         string
		chartName    string
		chartVersion string
		wantVersion  string
		wantErr      string
	}{
		{
			name:         "exact match",
			chartName:    "chart",
			chartVersion: "0.0.1",
			wantVersion:  "0.0.1",
		},
		{
			name:         "stable version",
			chartName:    "chart",
			chartVersion: "",
			wantVersion:  "1.0.0",
		},
		{
			name:         "stable version (asterisk)",
			chartName:    "chart",
			chartVersion: "*",
			wantVersion:  "1.0.0",
		},
		{
			name:         "semver range",
			chartName:    "chart",
			chartVersion: "<1.0.0",
			wantVersion:  "0.2.0",
		},
		{
			name:         "unfulfilled range",
			chartName:    "chart",
			chartVersion: ">2.0.0",
			wantErr:      "no 'chart' chart with version matching '>2.0.0' found",
		},
		{
			name:      "invalid chart",
			chartName: "non-existing",
			wantErr:   repo.ErrNoChartName.Error(),
		},
		{
			name:         "match newest if ambiguous",
			chartName:    "chart",
			chartVersion: "0.1.5",
			wantVersion:  "0.1.5+c.now",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cv, err := r.GetChartVersion(tt.chartName, tt.chartVersion)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(cv).To(BeNil())
				return
			}
			g.Expect(cv).ToNot(BeNil())
			g.Expect(cv.Metadata.Name).To(Equal(tt.chartName))
			g.Expect(cv.Metadata.Version).To(Equal(tt.wantVersion))
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestChartRepository_DownloadChart(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		chartVersion *repo.ChartVersion
		wantURL      string
		wantErr      bool
	}{
		{
			name: "relative URL",
			url:  "https://example.com",
			chartVersion: &repo.ChartVersion{
				Metadata: &chart.Metadata{Name: "chart"},
				URLs:     []string{"charts/foo-1.0.0.tgz"},
			},
			wantURL: "https://example.com/charts/foo-1.0.0.tgz",
		},
		{
			name:         "no chart URL",
			chartVersion: &repo.ChartVersion{Metadata: &chart.Metadata{Name: "chart"}},
			wantErr:      true,
		},
		{
			name: "invalid chart URL",
			chartVersion: &repo.ChartVersion{
				Metadata: &chart.Metadata{Name: "chart"},
				URLs:     []string{"https://ex ample.com/charts/foo-1.0.0.tgz"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()

			mg := mockGetter{}
			r := &ChartRepository{
				URL:    tt.url,
				Client: &mg,
			}
			res, err := r.DownloadChart(tt.chartVersion)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				g.Expect(res).To(BeNil())
				return
			}
			g.Expect(mg.LastCalledURL).To(Equal(tt.wantURL))
			g.Expect(res).ToNot(BeNil())
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestChartRepository_DownloadIndex(t *testing.T) {
	g := NewWithT(t)

	b, err := os.ReadFile(chartmuseumTestFile)
	g.Expect(err).ToNot(HaveOccurred())

	mg := mockGetter{Response: b}
	r := &ChartRepository{
		URL:    "https://example.com",
		Client: &mg,
	}

	buf := bytes.NewBuffer([]byte{})
	g.Expect(r.DownloadIndex(buf)).To(Succeed())
	g.Expect(buf.Bytes()).To(Equal(b))
	g.Expect(mg.LastCalledURL).To(Equal(r.URL + "/index.yaml"))
	g.Expect(err).To(BeNil())
}

func TestChartRepository_LoadIndexFromBytes(t *testing.T) {
	tests := []struct {
		name        string
		b           []byte
		wantName    string
		wantVersion string
		wantDigest  string
		wantErr     string
	}{
		{
			name: "index",
			b: []byte(`
apiVersion: v1
entries:
  nginx:
    - urls:
        - https://kubernetes-charts.storage.googleapis.com/nginx-0.2.0.tgz
      name: nginx
      description: string
      version: 0.2.0
      home: https://github.com/something/else
      digest: "sha256:1234567890abcdef"
`),
			wantName:    "nginx",
			wantVersion: "0.2.0",
			wantDigest:  "sha256:1234567890abcdef",
		},
		{
			name: "index without API version",
			b: []byte(`entries:
  nginx:
    - name: nginx`),
			wantErr: "no API version specified",
		},
		{
			name: "index with duplicate entry",
			b: []byte(`apiVersion: v1
entries:
  nginx:
    - name: nginx"
  nginx:
    - name: nginx`),
			wantErr: "key \"nginx\" already set in map",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()

			r := newChartRepository()
			err := r.LoadIndexFromBytes(tt.b)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(r.Index).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(r.Index).ToNot(BeNil())
			got, err := r.Index.Get(tt.wantName, tt.wantVersion)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got.Digest).To(Equal(tt.wantDigest))
		})
	}
}

func TestChartRepository_LoadIndexFromBytes_Unordered(t *testing.T) {
	b, err := os.ReadFile(unorderedTestFile)
	if err != nil {
		t.Fatal(err)
	}
	r := newChartRepository()
	err = r.LoadIndexFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	verifyLocalIndex(t, r.Index)
}

// Index load tests are derived from https://github.com/helm/helm/blob/v3.3.4/pkg/repo/index_test.go#L108
// to ensure parity with Helm behaviour.
func TestChartRepository_LoadIndexFromFile(t *testing.T) {
	g := NewWithT(t)

	// Create an index file that exceeds the max index size.
	tmpDir := t.TempDir()
	bigIndexFile := filepath.Join(tmpDir, "index.yaml")
	data := make([]byte, helm.MaxIndexSize+10)
	g.Expect(os.WriteFile(bigIndexFile, data, 0o640)).ToNot(HaveOccurred())

	tests := []struct {
		name     string
		filename string
		wantErr  string
	}{
		{
			name:     "regular index file",
			filename: testFile,
		},
		{
			name:     "chartmuseum index file",
			filename: chartmuseumTestFile,
		},
		{
			name:     "error if index size exceeds max size",
			filename: bigIndexFile,
			wantErr:  "size of index 'index.yaml' exceeds",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := newChartRepository()
			err := r.LoadFromFile(tt.filename)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())

			verifyLocalIndex(t, r.Index)
		})
	}
}

func TestChartRepository_CacheIndex(t *testing.T) {
	g := NewWithT(t)

	mg := mockGetter{Response: []byte("foo")}
	expectSum := fmt.Sprintf("%x", sha256.Sum256(mg.Response))

	r := newChartRepository()
	r.URL = "https://example.com"
	r.Client = &mg

	sum, err := r.CacheIndex()
	g.Expect(err).To(Not(HaveOccurred()))

	g.Expect(r.CachePath).ToNot(BeEmpty())
	defer os.RemoveAll(r.CachePath)
	g.Expect(r.CachePath).To(BeARegularFile())
	b, _ := os.ReadFile(r.CachePath)

	g.Expect(b).To(Equal(mg.Response))
	g.Expect(sum).To(BeEquivalentTo(expectSum))
}

func TestChartRepository_StrategicallyLoadIndex(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	r.Index = repo.NewIndexFile()
	g.Expect(r.StrategicallyLoadIndex()).To(Succeed())
	g.Expect(r.CachePath).To(BeEmpty())
	g.Expect(r.Cached).To(BeFalse())

	r.Index = nil
	r.CachePath = "/invalid/cache/index/path.yaml"
	err := r.StrategicallyLoadIndex()
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("/invalid/cache/index/path.yaml: no such file or directory"))
	g.Expect(r.Cached).To(BeFalse())

	r.CachePath = ""
	r.Client = &mockGetter{}
	err = r.StrategicallyLoadIndex()
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("no API version specified"))
	g.Expect(r.Cached).To(BeTrue())
	g.Expect(r.RemoveCache()).To(Succeed())
}

func TestChartRepository_CacheIndexInMemory(t *testing.T) {
	g := NewWithT(t)

	interval, _ := time.ParseDuration("5s")
	memCache := cache.New(1, interval)
	indexPath := "/multi-tenent-safe/mock/index.yaml"
	r := newChartRepository()
	r.Index = repo.NewIndexFile()
	indexFile := *r.Index
	g.Expect(
		indexFile.MustAdd(
			&chart.Metadata{
				Name:    "grafana",
				Version: "6.17.4",
			},
			"grafana-6.17.4.tgz",
			"http://example.com/charts",
			"sha256:1234567890abc",
		)).To(Succeed())
	indexFile.WriteFile(indexPath, 0o640)
	ttl, _ := time.ParseDuration("1m")
	r.SetMemCache(indexPath, memCache, ttl, func(event string) {
		fmt.Println(event)
	})
	r.CacheIndexInMemory()
	_, cacheHit := r.IndexCache.Get(indexPath)
	g.Expect(cacheHit).To(Equal(true))
	r.Unload()
	g.Expect(r.Index).To(BeNil())
	g.Expect(r.StrategicallyLoadIndex()).To(Succeed())
	g.Expect(r.Index.Entries["grafana"][0].Digest).To(Equal("sha256:1234567890abc"))
}

func TestChartRepository_LoadFromCache(t *testing.T) {
	tests := []struct {
		name      string
		cachePath string
		wantErr   string
	}{
		{
			name:      "cache path",
			cachePath: chartmuseumTestFile,
		},
		{
			name:      "invalid cache path",
			cachePath: "invalid",
			wantErr:   "stat invalid: no such file",
		},
		{
			name:      "no cache path",
			cachePath: "",
			wantErr:   "no cache path set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			r := newChartRepository()
			r.CachePath = tt.cachePath
			err := r.LoadFromCache()
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(r.Index).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			verifyLocalIndex(t, r.Index)
		})
	}
}

func TestChartRepository_HasIndex(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	g.Expect(r.HasIndex()).To(BeFalse())
	r.Index = repo.NewIndexFile()
	g.Expect(r.HasIndex()).To(BeTrue())
}

func TestChartRepository_HasCacheFile(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	g.Expect(r.HasCacheFile()).To(BeFalse())
	r.CachePath = "foo"
	g.Expect(r.HasCacheFile()).To(BeTrue())
}

func TestChartRepository_UnloadIndex(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	g.Expect(r.HasIndex()).To(BeFalse())
	r.Index = repo.NewIndexFile()
	r.Unload()
	g.Expect(r.Index).To(BeNil())
}

func verifyLocalIndex(t *testing.T, i *repo.IndexFile) {
	g := NewWithT(t)

	g.Expect(i.Entries).ToNot(BeNil())
	g.Expect(i.Entries).To(HaveLen(3), "expected 3 entries in index file")

	alpine, ok := i.Entries["alpine"]
	g.Expect(ok).To(BeTrue(), "expected 'alpine' entry to exist")
	g.Expect(alpine).To(HaveLen(1), "'alpine' should have 1 entry")

	nginx, ok := i.Entries["nginx"]
	g.Expect(ok).To(BeTrue(), "expected 'nginx' entry to exist")
	g.Expect(nginx).To(HaveLen(2), "'nginx' should have 2 entries")

	expects := []*repo.ChartVersion{
		{
			Metadata: &chart.Metadata{
				Name:        "alpine",
				Description: "string",
				Version:     "1.0.0",
				Keywords:    []string{"linux", "alpine", "small", "sumtin"},
				Home:        "https://github.com/something",
			},
			URLs: []string{
				"https://kubernetes-charts.storage.googleapis.com/alpine-1.0.0.tgz",
				"http://storage2.googleapis.com/kubernetes-charts/alpine-1.0.0.tgz",
			},
			Digest: "sha256:1234567890abcdef",
		},
		{
			Metadata: &chart.Metadata{
				Name:        "nginx",
				Description: "string",
				Version:     "0.2.0",
				Keywords:    []string{"popular", "web server", "proxy"},
				Home:        "https://github.com/something/else",
			},
			URLs: []string{
				"https://kubernetes-charts.storage.googleapis.com/nginx-0.2.0.tgz",
			},
			Digest: "sha256:1234567890abcdef",
		},
		{
			Metadata: &chart.Metadata{
				Name:        "nginx",
				Description: "string",
				Version:     "0.1.0",
				Keywords:    []string{"popular", "web server", "proxy"},
				Home:        "https://github.com/something",
			},
			URLs: []string{
				"https://kubernetes-charts.storage.googleapis.com/nginx-0.1.0.tgz",
			},
			Digest: "sha256:1234567890abcdef",
		},
	}
	tests := []*repo.ChartVersion{alpine[0], nginx[0], nginx[1]}

	for i, tt := range tests {
		expect := expects[i]
		g.Expect(tt.Name).To(Equal(expect.Name))
		g.Expect(tt.Description).To(Equal(expect.Description))
		g.Expect(tt.Version).To(Equal(expect.Version))
		g.Expect(tt.Digest).To(Equal(expect.Digest))
		g.Expect(tt.Home).To(Equal(expect.Home))
		g.Expect(tt.URLs).To(ContainElements(expect.URLs))
		g.Expect(tt.Keywords).To(ContainElements(expect.Keywords))
	}
}

func TestChartRepository_RemoveCache(t *testing.T) {
	g := NewWithT(t)

	tmpFile, err := os.CreateTemp("", "remove-cache-")
	g.Expect(err).ToNot(HaveOccurred())
	defer os.Remove(tmpFile.Name())

	r := newChartRepository()
	r.CachePath = tmpFile.Name()
	r.Cached = true

	g.Expect(r.RemoveCache()).To(Succeed())
	g.Expect(r.CachePath).To(BeEmpty())
	g.Expect(r.Cached).To(BeFalse())
	g.Expect(tmpFile.Name()).ToNot(BeAnExistingFile())

	r.CachePath = tmpFile.Name()
	r.Cached = true

	g.Expect(r.RemoveCache()).To(Succeed())
	g.Expect(r.CachePath).To(BeEmpty())
	g.Expect(r.Cached).To(BeFalse())
}
