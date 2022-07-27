/*
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

package repository

import (
	"bytes"
	"fmt"
	"net/url"
	"path"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"
)

type OCIMockGetter struct {
	Response      []byte
	LastCalledURL string
}

func (g *OCIMockGetter) Get(u string, _ ...helmgetter.Option) (*bytes.Buffer, error) {
	r := g.Response
	g.LastCalledURL = u
	return bytes.NewBuffer(r), nil
}

type mockRegistryClient struct {
	tags          []string
	LastCalledURL string
}

func (m *mockRegistryClient) Tags(urlStr string) ([]string, error) {
	m.LastCalledURL = urlStr
	return m.tags, nil
}

func (m *mockRegistryClient) Login(url string, opts ...registry.LoginOption) error {
	m.LastCalledURL = url
	return nil
}

func (m *mockRegistryClient) Logout(url string, opts ...registry.LogoutOption) error {
	m.LastCalledURL = url
	return nil
}

func TestNewOCIChartRepository(t *testing.T) {
	registryClient := &mockRegistryClient{}
	url := "oci://localhost:5000/my_repo"
	providers := helmgetter.Providers{
		helmgetter.Provider{
			Schemes: []string{"oci"},
			New:     helmgetter.NewOCIGetter,
		},
	}
	options := []helmgetter.Option{helmgetter.WithBasicAuth("username", "password")}
	t.Run("should construct chart registry", func(t *testing.T) {
		g := NewWithT(t)
		r, err := NewOCIChartRepository(url, WithOCIGetter(providers), WithOCIGetterOptions(options), WithOCIRegistryClient(registryClient))
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(r).ToNot(BeNil())
		g.Expect(r.URL.Host).To(Equal("localhost:5000"))
		g.Expect(r.Client).ToNot(BeNil())
		g.Expect(r.Options).To(Equal(options))
		g.Expect(r.RegistryClient).To(Equal(registryClient))
	})

	t.Run("should return error on invalid url", func(t *testing.T) {
		g := NewWithT(t)
		r, err := NewOCIChartRepository("oci://localhost:5000 /my_repo", WithOCIGetter(providers), WithOCIGetterOptions(options), WithOCIRegistryClient(registryClient))
		g.Expect(err).To(HaveOccurred())
		g.Expect(r).To(BeNil())
	})

}

func TestOCIChartRepository_Get(t *testing.T) {
	registryClient := &mockRegistryClient{
		tags: []string{
			"0.0.1",
			"0.1.0",
			"0.1.1",
			"0.1.5+b.min.minute",
			"0.1.5+a.min.hour",
			"0.1.5+c.now",
			"0.2.0",
			"0.9.0",
			"0.10.0",
			"1.0.0",
			"1.1.0-rc.1",
		},
	}

	providers := helmgetter.Providers{
		helmgetter.Provider{
			Schemes: []string{"oci"},
			New:     helmgetter.NewOCIGetter,
		},
	}
	testURL := "oci://localhost:5000/my_repo"

	testCases := []struct {
		name           string
		registryClient RegistryClient
		url            string
		version        string
		expected       string
		expectedErr    string
	}{
		{
			name:           "should return latest stable version",
			registryClient: registryClient,
			version:        "",
			url:            testURL,
			expected:       "1.0.0",
		},
		{
			name:           "should return latest stable version (asterisk)",
			registryClient: registryClient,
			version:        "*",
			url:            testURL,
			expected:       "1.0.0",
		},
		{
			name:           "should return latest stable version (semver range)",
			registryClient: registryClient,
			version:        ">=0.1.5",
			url:            testURL,
			expected:       "1.0.0",
		},
		{
			name:           "should return 0.2.0 (semver range)",
			registryClient: registryClient,
			version:        "0.2.x",
			url:            testURL,
			expected:       "0.2.0",
		},
		{
			name:           "should return a perfect match",
			registryClient: nil,
			version:        "0.1.0",
			url:            testURL,
			expected:       "0.1.0",
		},
		{
			name:           "should return 0.10.0",
			registryClient: registryClient,
			version:        "0.*",
			url:            testURL,
			expected:       "0.10.0",
		},
		{
			name:           "should an error for unfulfilled range",
			registryClient: registryClient,
			version:        ">2.0.0",
			url:            testURL,
			expectedErr:    "could not locate a version matching provided version string >2.0.0",
		},
		{
			name:           "shouldn't error out with trailing slash",
			registryClient: registryClient,
			version:        "",
			url:            "oci://localhost:5000/my_repo/",
			expected:       "1.0.0",
		},
	}

	for _, tc := range testCases {

		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			r, err := NewOCIChartRepository(tc.url, WithOCIRegistryClient(tc.registryClient), WithOCIGetter(providers))
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(r).ToNot(BeNil())

			chart := "podinfo"
			cv, err := r.GetChartVersion(chart, tc.version)
			if tc.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tc.expectedErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())

			u, err := url.Parse(tc.url)
			g.Expect(err).ToNot(HaveOccurred())
			u.Path = path.Join(u.Path, chart)
			g.Expect(cv.URLs[0]).To(Equal(fmt.Sprintf("%s:%s", u.String(), tc.expected)))
			g.Expect(registryClient.LastCalledURL).To(Equal(strings.TrimPrefix(u.String(), fmt.Sprintf("%s://", registry.OCIScheme))))
		})
	}
}

func TestOCIChartRepository_DownloadChart(t *testing.T) {
	client := &mockRegistryClient{}
	testCases := []struct {
		name         string
		url          string
		chartVersion *repo.ChartVersion
		expected     string
		expectedErr  bool
	}{
		{
			name: "should download chart",
			url:  "oci://localhost:5000/my_repo",
			chartVersion: &repo.ChartVersion{
				Metadata: &chart.Metadata{Name: "chart"},
				URLs:     []string{"oci://localhost:5000/my_repo/podinfo:1.0.0"},
			},
			expected: "oci://localhost:5000/my_repo/podinfo:1.0.0",
		},
		{
			name:         "no chart URL",
			url:          "",
			chartVersion: &repo.ChartVersion{Metadata: &chart.Metadata{Name: "chart"}},
			expectedErr:  true,
		},
		{
			name: "invalid chart URL",
			url:  "oci://localhost:5000/my_repo",
			chartVersion: &repo.ChartVersion{
				Metadata: &chart.Metadata{Name: "chart"},
				URLs:     []string{"oci://localhost:5000 /my_repo/podinfo:1.0.0"},
			},
			expectedErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()
			mg := OCIMockGetter{}
			u, err := url.Parse(tc.url)
			g.Expect(err).ToNot(HaveOccurred())
			r := OCIChartRepository{
				Client: &mg,
				URL:    *u,
			}
			r.Client = &mg
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(r).ToNot(BeNil())
			res, err := r.DownloadChart(tc.chartVersion)
			if tc.expectedErr {
				g.Expect(err).To(HaveOccurred())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(client.LastCalledURL).To(Equal(tc.expected))
			g.Expect(res).ToNot(BeNil())
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}
