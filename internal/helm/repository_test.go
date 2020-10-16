/*
Copyright 2020 The Flux CD contributors.

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
	"bytes"
	"io/ioutil"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
)

const (
	testfile            = "testdata/local-index.yaml"
	chartmuseumtestfile = "testdata/chartmuseum-index.yaml"
	unorderedtestfile   = "testdata/local-index-unordered.yaml"
	indexWithDuplicates = `
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
  nginx:
    - urls:
        - https://kubernetes-charts.storage.googleapis.com/alpine-1.0.0.tgz
        - http://storage2.googleapis.com/kubernetes-charts/alpine-1.0.0.tgz
      name: alpine
      description: string
      version: 1.0.0
      home: https://github.com/something
      digest: "sha256:1234567890abcdef"
`
)

func TestNewChartRepository(t *testing.T) {
	repositoryURL := "https://example.com"
	providers := getter.Providers{
		getter.Provider{
			Schemes: []string{"https"},
			New:     getter.NewHTTPGetter,
		},
	}
	options := []getter.Option{getter.WithBasicAuth("username", "password")}

	t.Run("should construct chart repository", func(t *testing.T) {
		r, err := NewChartRepository(repositoryURL, providers, options)
		if err != nil {
			t.Error(err)
		}
		if got := r.URL; got != repositoryURL {
			t.Fatalf("Expecting %q repository URL, got: %q", repositoryURL, got)
		}
		if r.Client == nil {
			t.Fatalf("Expecting client, got nil")
		}
		if !reflect.DeepEqual(r.Options, options) {
			t.Fatalf("Client options mismatth")
		}
	})

	t.Run("should error on URL parsing failure", func(t *testing.T) {
		_, err := NewChartRepository("https://ex ample.com", nil, nil)
		switch err.(type) {
		case *url.Error:
		default:
			t.Fatalf("Expecting URL error, got: %v", err)
		}
	})

	t.Run("should error on unsupported scheme", func(t *testing.T) {
		_, err := NewChartRepository("http://example.com", providers, nil)
		if err == nil {
			t.Fatalf("Expecting unsupported scheme error")
		}
	})
}

func TestChartRepository_Get(t *testing.T) {
	i := repo.NewIndexFile()
	i.Add(&chart.Metadata{Name: "chart", Version: "0.0.1"}, "chart-0.0.1.tgz", "http://example.com/charts", "sha256:1234567890")
	i.Add(&chart.Metadata{Name: "chart", Version: "0.1.0"}, "chart-0.1.0.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Add(&chart.Metadata{Name: "chart", Version: "0.1.1"}, "chart-0.1.1.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Add(&chart.Metadata{Name: "chart", Version: "0.1.5+b.min.minute"}, "chart-0.1.5+b.min.minute.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Entries["chart"][len(i.Entries["chart"])-1].Created = time.Now().Add(-time.Minute)
	i.Add(&chart.Metadata{Name: "chart", Version: "0.1.5+a.min.hour"}, "chart-0.1.5+a.min.hour.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Entries["chart"][len(i.Entries["chart"])-1].Created = time.Now().Add(-time.Hour)
	i.Add(&chart.Metadata{Name: "chart", Version: "0.1.5+c.now"}, "chart-0.1.5+c.now.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Add(&chart.Metadata{Name: "chart", Version: "0.2.0"}, "chart-0.2.0.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Add(&chart.Metadata{Name: "chart", Version: "1.0.0"}, "chart-1.0.0.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Add(&chart.Metadata{Name: "chart", Version: "1.0.0"}, "chart-1.0.0.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.Add(&chart.Metadata{Name: "chart", Version: "1.5.0-rc.1"}, "chart-1.5.0-rc.1.tgz", "http://example.com/charts", "sha256:1234567890abc")
	i.SortEntries()
	r := &ChartRepository{Index: i}

	tests := []struct {
		name         string
		chartName    string
		chartVersion string
		wantVersion  string
		wantErr      bool
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
			wantErr:      true,
		},
		{
			name:      "invalid chart",
			chartName: "non-existing",
			wantErr:   true,
		},
		{
			name:         "non-semver",
			chartName:    "chart",
			chartVersion: "v1x5",
			wantErr:      true,
		},
		{
			name:         "do not match pre-release",
			chartName:    "chart",
			chartVersion: ">=1.5.0",
			wantErr:      true,
		},
		{
			name:         "match pre-release",
			chartName:    "chart",
			chartVersion: ">=1.5.0-0",
			wantVersion:  "1.5.0-rc.1",
		},
		{
			name:         "match newest build",
			chartName:    "chart",
			chartVersion: "0.1.5",
			wantVersion:  "0.1.5+c.now",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cv, err := r.Get(tt.chartName, tt.chartVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !strings.Contains(cv.Metadata.Version, tt.wantVersion) {
				t.Errorf("Get() unexpected version = %s, want = %s", cv.Metadata.Version, tt.wantVersion)
			}
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
		t.Run(tt.name, func(t *testing.T) {
			mg := mockGetter{}
			r := &ChartRepository{
				URL:    tt.url,
				Client: &mg,
			}
			_, err := r.DownloadChart(tt.chartVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("DownloadChart() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && mg.requestedURL != tt.wantURL {
				t.Errorf("DownloadChart() requested URL = %s, wantURL %s", mg.requestedURL, tt.wantURL)
			}
		})
	}
}

func TestChartRepository_DownloadIndex(t *testing.T) {
	b, err := ioutil.ReadFile(chartmuseumtestfile)
	if err != nil {
		t.Fatal(err)
	}
	mg := mockGetter{response: b}
	r := &ChartRepository{
		URL:    "https://example.com",
		Client: &mg,
	}
	if err := r.DownloadIndex(); err != nil {
		t.Fatal(err)
	}
	if expected := r.URL + "/index.yaml"; mg.requestedURL != expected {
		t.Errorf("DownloadIndex() requested URL = %s, wantURL %s", mg.requestedURL, expected)
	}
	verifyLocalIndex(t, r.Index)
}

// Index load tests are derived from https://github.com/helm/helm/blob/v3.3.4/pkg/repo/index_test.go#L108
// to ensure parity with Helm behaviour.
func TestChartRepository_LoadIndex(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{
			name:     "regular index file",
			filename: testfile,
		},
		{
			name:     "chartmuseum index file",
			filename: chartmuseumtestfile,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := ioutil.ReadFile(tt.filename)
			if err != nil {
				t.Fatal(err)
			}
			r := &ChartRepository{}
			err = r.LoadIndex(b)
			if err != nil {
				t.Fatal(err)
			}
			verifyLocalIndex(t, r.Index)
		})
	}
}

func TestChartRepository_LoadIndex_Duplicates(t *testing.T) {
	r := &ChartRepository{}
	if err := r.LoadIndex([]byte(indexWithDuplicates)); err == nil {
		t.Errorf("Expected an error when duplicate entries are present")
	}
}

func TestChartRepository_LoadIndex_Unordered(t *testing.T) {
	b, err := ioutil.ReadFile(unorderedtestfile)
	if err != nil {
		t.Fatal(err)
	}
	r := &ChartRepository{}
	err = r.LoadIndex(b)
	if err != nil {
		t.Fatal(err)
	}
	verifyLocalIndex(t, r.Index)
}

func verifyLocalIndex(t *testing.T, i *repo.IndexFile) {
	numEntries := len(i.Entries)
	if numEntries != 3 {
		t.Errorf("Expected 3 entries in index file but got %d", numEntries)
	}

	alpine, ok := i.Entries["alpine"]
	if !ok {
		t.Fatalf("'alpine' section not found.")
	}

	if l := len(alpine); l != 1 {
		t.Fatalf("'alpine' should have 1 chart, got %d", l)
	}

	nginx, ok := i.Entries["nginx"]
	if !ok || len(nginx) != 2 {
		t.Fatalf("Expected 2 nginx entries")
	}

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
		if tt.Name != expect.Name {
			t.Errorf("Expected name %q, got %q", expect.Name, tt.Name)
		}
		if tt.Description != expect.Description {
			t.Errorf("Expected description %q, got %q", expect.Description, tt.Description)
		}
		if tt.Version != expect.Version {
			t.Errorf("Expected version %q, got %q", expect.Version, tt.Version)
		}
		if tt.Digest != expect.Digest {
			t.Errorf("Expected digest %q, got %q", expect.Digest, tt.Digest)
		}
		if tt.Home != expect.Home {
			t.Errorf("Expected home %q, got %q", expect.Home, tt.Home)
		}

		for i, url := range tt.URLs {
			if url != expect.URLs[i] {
				t.Errorf("Expected URL %q, got %q", expect.URLs[i], url)
			}
		}
		for i, kw := range tt.Keywords {
			if kw != expect.Keywords[i] {
				t.Errorf("Expected keywords %q, got %q", expect.Keywords[i], kw)
			}
		}
	}
}

type mockGetter struct {
	requestedURL string
	response     []byte
}

func (g *mockGetter) Get(url string, options ...getter.Option) (*bytes.Buffer, error) {
	g.requestedURL = url
	return bytes.NewBuffer(g.response), nil
}
