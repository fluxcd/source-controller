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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
	"helm.sh/helm/v3/pkg/chart"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/werf/nelm-source-controller/internal/helm"
)

var now = time.Now()

const (
	testFile                = "../testdata/local-index.yaml"
	chartmuseumTestFile     = "../testdata/chartmuseum-index.yaml"
	chartmuseumJSONTestFile = "../testdata/chartmuseum-index.json"
	unorderedTestFile       = "../testdata/local-index-unordered.yaml"
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

// Index load tests are derived from https://github.com/helm/helm/blob/v3.3.4/pkg/repo/index_test.go#L108
// to ensure parity with Helm behaviour.
func TestIndexFromFile(t *testing.T) {
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
			name:     "chartmuseum json index file",
			filename: chartmuseumJSONTestFile,
		},
		{
			name:     "error if index size exceeds max size",
			filename: bigIndexFile,
			wantErr:  "exceeds the maximum index file size",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			i, err := IndexFromFile(tt.filename)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())

			verifyLocalIndex(t, i)
		})
	}
}

func TestIndexFromBytes(t *testing.T) {
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

			i, err := IndexFromBytes(tt.b)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(i).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(i).ToNot(BeNil())
			got, err := i.Get(tt.wantName, tt.wantVersion)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got.Digest).To(Equal(tt.wantDigest))
		})
	}
}

func TestIndexFromBytes_Unordered(t *testing.T) {
	b, err := os.ReadFile(unorderedTestFile)
	if err != nil {
		t.Fatal(err)
	}
	i, err := IndexFromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	verifyLocalIndex(t, i)
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

		r, err := NewChartRepository(repositoryURL, "", providers, nil, options...)
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

func TestChartRepository_GetChartVersion(t *testing.T) {
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

func TestChartRepository_CacheIndex(t *testing.T) {
	g := NewWithT(t)

	mg := mockGetter{Response: []byte("foo")}

	r := newChartRepository()
	r.URL = "https://example.com"
	r.Client = &mg
	r.digests["key"] = "value"

	err := r.CacheIndex()
	g.Expect(err).To(Not(HaveOccurred()))

	g.Expect(r.Path).ToNot(BeEmpty())
	t.Cleanup(func() { _ = os.Remove(r.Path) })

	g.Expect(r.Path).To(BeARegularFile())
	b, _ := os.ReadFile(r.Path)
	g.Expect(b).To(Equal(mg.Response))

	g.Expect(r.digests).To(BeEmpty())
}

func TestChartRepository_ToJSON(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	r.Path = chartmuseumTestFile

	_, err := r.ToJSON()
	g.Expect(err).To(HaveOccurred())

	g.Expect(r.LoadFromPath()).To(Succeed())
	b, err := r.ToJSON()
	g.Expect(err).ToNot(HaveOccurred())

	jsonBytes, err := os.ReadFile(chartmuseumJSONTestFile)
	jsonBytes = bytes.TrimRight(jsonBytes, "\n")
	g.Expect(err).To(Not(HaveOccurred()))
	g.Expect(string(b)).To(Equal(string(jsonBytes)))
}

func TestChartRepository_DownloadIndex(t *testing.T) {
	g := NewWithT(t)

	b, err := os.ReadFile(chartmuseumTestFile)
	g.Expect(err).ToNot(HaveOccurred())

	mg := mockGetter{Response: b}
	r := &ChartRepository{
		URL:     "https://example.com",
		Client:  &mg,
		RWMutex: &sync.RWMutex{},
	}

	t.Run("download index", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{})
		g.Expect(r.DownloadIndex(buf, helm.MaxIndexSize)).To(Succeed())
		g.Expect(buf.Bytes()).To(Equal(b))
		g.Expect(mg.LastCalledURL).To(Equal(r.URL + "/index.yaml"))
		g.Expect(err).To(BeNil())
	})

	t.Run("download index size error", func(t *testing.T) {
		buf := bytes.NewBuffer([]byte{})
		g.Expect(r.DownloadIndex(buf, int64(len(b)-1))).To(HaveOccurred())
		g.Expect(mg.LastCalledURL).To(Equal(r.URL + "/index.yaml"))
	})
}

func TestChartRepository_StrategicallyLoadIndex(t *testing.T) {
	t.Run("loads from path", func(t *testing.T) {
		g := NewWithT(t)

		i := filepath.Join(t.TempDir(), "index.yaml")
		g.Expect(os.WriteFile(i, []byte(`apiVersion: v1`), 0o600)).To(Succeed())

		r := newChartRepository()
		r.Path = i

		err := r.StrategicallyLoadIndex()
		g.Expect(err).To(Succeed())
		g.Expect(r.Index).ToNot(BeNil())
	})

	t.Run("loads from client", func(t *testing.T) {
		g := NewWithT(t)

		r := newChartRepository()
		r.Client = &mockGetter{
			Response: []byte(`apiVersion: v1`),
		}
		t.Cleanup(func() {
			_ = os.Remove(r.Path)
		})

		err := r.StrategicallyLoadIndex()
		g.Expect(err).To(Succeed())
		g.Expect(r.Path).ToNot(BeEmpty())
		g.Expect(r.Index).ToNot(BeNil())
	})

	t.Run("skips if index is already loaded", func(t *testing.T) {
		g := NewWithT(t)

		r := newChartRepository()
		r.Index = repo.NewIndexFile()

		g.Expect(r.StrategicallyLoadIndex()).To(Succeed())
	})
}

func TestChartRepository_LoadFromPath(t *testing.T) {
	t.Run("loads index", func(t *testing.T) {
		g := NewWithT(t)

		i := filepath.Join(t.TempDir(), "index.yaml")
		g.Expect(os.WriteFile(i, []byte(`apiVersion: v1`), 0o600)).To(Succeed())

		r := newChartRepository()
		r.Path = i

		g.Expect(r.LoadFromPath()).To(Succeed())
		g.Expect(r.Index).ToNot(BeNil())
	})

	t.Run("no cache path", func(t *testing.T) {
		g := NewWithT(t)

		err := newChartRepository().LoadFromPath()
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("no cache path"))
	})

	t.Run("index load error", func(t *testing.T) {
		g := NewWithT(t)

		r := newChartRepository()
		r.Path = filepath.Join(t.TempDir(), "index.yaml")

		err := r.LoadFromPath()
		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue())
	})
}

func TestChartRepository_Digest(t *testing.T) {
	t.Run("with algorithm", func(t *testing.T) {
		g := NewWithT(t)

		p := filepath.Join(t.TempDir(), "index.yaml")
		g.Expect(repo.NewIndexFile().WriteFile(p, 0o600)).To(Succeed())

		r := newChartRepository()
		r.Path = p

		for _, algo := range []digest.Algorithm{digest.SHA256, digest.SHA512} {
			t.Run(algo.String(), func(t *testing.T) {
				g := NewWithT(t)

				d := r.Digest(algo)
				g.Expect(d).ToNot(BeEmpty())
				g.Expect(d.Algorithm()).To(Equal(algo))
				g.Expect(r.digests[algo]).To(Equal(d))
			})
		}
	})

	t.Run("without path", func(t *testing.T) {
		g := NewWithT(t)

		r := newChartRepository()
		g.Expect(r.Digest(digest.SHA256)).To(BeEmpty())
	})

	t.Run("from cache", func(t *testing.T) {
		g := NewWithT(t)

		algo := digest.SHA256
		expect := digest.Digest("sha256:fake")

		i := filepath.Join(t.TempDir(), "index.yaml")
		g.Expect(os.WriteFile(i, []byte(`apiVersion: v1`), 0o600)).To(Succeed())

		r := newChartRepository()
		r.Path = i
		r.digests[algo] = expect

		g.Expect(r.Digest(algo)).To(Equal(expect))
	})
}

func TestChartRepository_HasIndex(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	g.Expect(r.HasIndex()).To(BeFalse())
	r.Index = repo.NewIndexFile()
	g.Expect(r.HasIndex()).To(BeTrue())
}

func TestChartRepository_HasFile(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	g.Expect(r.HasFile()).To(BeFalse())

	i := filepath.Join(t.TempDir(), "index.yaml")
	g.Expect(os.WriteFile(i, []byte(`apiVersion: v1`), 0o600)).To(Succeed())
	r.Path = i
	g.Expect(r.HasFile()).To(BeTrue())
}

func TestChartRepository_Clear(t *testing.T) {
	t.Run("without index", func(t *testing.T) {
		g := NewWithT(t)

		r := newChartRepository()
		g.Expect(r.Clear()).To(Succeed())
	})

	t.Run("with index", func(t *testing.T) {
		g := NewWithT(t)

		r := newChartRepository()
		r.Index = repo.NewIndexFile()

		g.Expect(r.Clear()).To(Succeed())
		g.Expect(r.Index).To(BeNil())
	})

	t.Run("with index and cached path", func(t *testing.T) {
		g := NewWithT(t)

		f, err := os.CreateTemp(t.TempDir(), "index-*.yaml")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(f.Close()).To(Succeed())

		r := newChartRepository()
		r.Path = f.Name()
		r.Index = repo.NewIndexFile()
		r.digests["key"] = "value"
		r.cached = true

		g.Expect(r.Clear()).To(Succeed())
		g.Expect(r.Index).To(BeNil())
		g.Expect(r.Path).To(BeEmpty())
		g.Expect(r.digests).To(BeEmpty())
		g.Expect(r.cached).To(BeFalse())
	})

	t.Run("with path", func(t *testing.T) {
		g := NewWithT(t)

		f, err := os.CreateTemp(t.TempDir(), "index-*.yaml")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(f.Close()).To(Succeed())

		r := newChartRepository()
		r.Path = f.Name()
		r.digests["key"] = "value"

		g.Expect(r.Clear()).To(Succeed())
		g.Expect(r.Path).ToNot(BeEmpty())
		g.Expect(r.Path).To(BeARegularFile())
		g.Expect(r.digests).To(BeEmpty())
	})
}

func TestChartRepository_Invalidate(t *testing.T) {
	g := NewWithT(t)

	r := newChartRepository()
	r.digests["key"] = "value"

	r.Invalidate()
	g.Expect(r.digests).To(BeEmpty())
}

func verifyLocalIndex(t *testing.T, i *repo.IndexFile) {
	g := NewWithT(t)

	g.Expect(i.Entries).ToNot(BeNil())
	g.Expect(i.Entries).To(HaveLen(4), "expected 4 entries in index file")

	alpine, ok := i.Entries["alpine"]
	g.Expect(ok).To(BeTrue(), "expected 'alpine' entry to exist")
	g.Expect(alpine).To(HaveLen(1), "'alpine' should have 1 entry")

	nginx, ok := i.Entries["nginx"]
	g.Expect(ok).To(BeTrue(), "expected 'nginx' entry to exist")
	g.Expect(nginx).To(HaveLen(2), "'nginx' should have 2 entries")

	broken, ok := i.Entries["xChartWithDuplicateDependenciesAndMissingAlias"]
	g.Expect(ok).To(BeTrue(), "expected 'xChartWithDuplicateDependenciesAndMissingAlias' entry to exist")
	g.Expect(broken).To(HaveLen(1), "'xChartWithDuplicateDependenciesAndMissingAlias' should have 1 entries")

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
		{
			Metadata: &chart.Metadata{
				Name:        "xChartWithDuplicateDependenciesAndMissingAlias",
				Description: "string",
				Version:     "1.2.3",
				Keywords:    []string{"broken", "still accepted"},
				Home:        "https://example.com/something",
				Dependencies: []*chart.Dependency{
					{Name: "kube-rbac-proxy", Version: "0.9.1"},
				},
			},
			URLs: []string{
				"https://kubernetes-charts.storage.googleapis.com/nginx-1.2.3.tgz",
			},
			Digest: "sha256:1234567890abcdef",
		},
	}
	tests := []*repo.ChartVersion{alpine[0], nginx[0], nginx[1], broken[0]}

	for i, tt := range tests {
		expect := expects[i]
		g.Expect(tt.Name).To(Equal(expect.Name))
		g.Expect(tt.Description).To(Equal(expect.Description))
		g.Expect(tt.Version).To(Equal(expect.Version))
		g.Expect(tt.Digest).To(Equal(expect.Digest))
		g.Expect(tt.Home).To(Equal(expect.Home))
		g.Expect(tt.URLs).To(ContainElements(expect.URLs))
		g.Expect(tt.Keywords).To(ContainElements(expect.Keywords))
		g.Expect(tt.Dependencies).To(ContainElements(expect.Dependencies))
	}
}

// This code is taken from https://github.com/helm/helm/blob/v3.15.2/pkg/repo/index_test.go#L601
// and refers to: https://github.com/helm/helm/issues/12748
func TestIgnoreSkippableChartValidationError(t *testing.T) {
	type TestCase struct {
		Input        error
		ErrorSkipped bool
	}
	testCases := map[string]TestCase{
		"nil": {
			Input: nil,
		},
		"generic_error": {
			Input: fmt.Errorf("foo"),
		},
		"non_skipped_validation_error": {
			Input: chart.ValidationError("chart.metadata.type must be application or library"),
		},
		"skipped_validation_error": {
			Input:        chart.ValidationErrorf("more than one dependency with name or alias %q", "foo"),
			ErrorSkipped: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := ignoreSkippableChartValidationError(tc.Input)

			if tc.Input == nil {
				if result != nil {
					t.Error("expected nil result for nil input")
				}
				return
			}

			if tc.ErrorSkipped {
				if result != nil {
					t.Error("expected nil result for skipped error")
				}
				return
			}

			if tc.Input != result {
				t.Error("expected the result equal to input")
			}

		})
	}
}

var indexWithFirstVersionInvalid = `
apiVersion: v1
entries:
  nginx:
    - urls:
        - https://charts.helm.sh/stable/alpine-1.0.0.tgz
        - http://storage2.googleapis.com/kubernetes-charts/alpine-1.0.0.tgz
      name: nginx
      version: 0..1.0
      description: string
      home: https://github.com/something
      digest: "sha256:1234567890abcdef"
    - urls:
        - https://charts.helm.sh/stable/nginx-0.2.0.tgz
      name: nginx
      description: string
      version: 0.2.0
      home: https://github.com/something/else
      digest: "sha256:1234567890abcdef"
`
var indexWithLastVersionInvalid = `
apiVersion: v1
entries:
  nginx:
    - urls:
        - https://charts.helm.sh/stable/nginx-0.2.0.tgz
      name: nginx
      description: string
      version: 0.2.0
      home: https://github.com/something/else
      digest: "sha256:1234567890abcdef"
    - urls:
        - https://charts.helm.sh/stable/alpine-1.0.0.tgz
        - http://storage2.googleapis.com/kubernetes-charts/alpine-1.0.0.tgz
      name: nginx
      version: 0..1.0
      description: string
      home: https://github.com/something
      digest: "sha256:1234567890abcdef"
`

func TestIndexFromBytes_InvalidEntries(t *testing.T) {
	tests := []struct {
		source string
		data   string
	}{
		{
			source: "indexWithFirstVersionInvalid",
			data:   indexWithFirstVersionInvalid,
		},
		{
			source: "indexWithLastVersionInvalid",
			data:   indexWithLastVersionInvalid,
		},
	}
	for _, tc := range tests {
		t.Run(tc.source, func(t *testing.T) {
			idx, err := IndexFromBytes([]byte(tc.data))
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			cvs := idx.Entries["nginx"]
			if len(cvs) == 0 {
				t.Error("expected one chart version not to be filtered out")
			}
			for _, v := range cvs {
				if v.Version == "0..1.0" {
					t.Error("malformed version was not filtered out")
				}
			}
		})
	}
}
