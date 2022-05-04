package repository

import (
	"bytes"
	"fmt"
	"net/url"
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

func (m *mockRegistryClient) Tags(url string) ([]string, error) {
	m.LastCalledURL = url
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

func TestOCIChartRepoisitory_Get(t *testing.T) {
	registryClient := &mockRegistryClient{
		tags: []string{
			"0.0.1",
			"0.1.0",
			"0.1.1",
			"0.1.5+b.min.minute",
			"0.1.5+a.min.hour",
			"0.1.5+c.now",
			"0.2.0",
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

	testCases := []struct {
		name        string
		version     string
		expected    string
		expectedErr string
	}{
		{
			name:     "should return latest stable version",
			version:  "",
			expected: "1.0.0",
		},
		{
			name:     "should return latest stable version (asterisk)",
			version:  "*",
			expected: "1.0.0",
		},
		{
			name:     "should return latest stable version (semver range)",
			version:  ">=0.1.5",
			expected: "1.0.0",
		},
		{
			name:     "should return 0.2.0 (semver range)",
			version:  "0.2.x",
			expected: "0.2.0",
		},
		{
			name:     "should return a perfect match",
			version:  "0.1.0",
			expected: "0.1.0",
		},
		{
			name:        "should an error for unfunfilled range",
			version:     ">2.0.0",
			expectedErr: "could not locate a version matching provided version string >2.0.0",
		},
	}

	url := "oci://localhost:5000/my_repo"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			r, err := NewOCIChartRepository(url, WithOCIRegistryClient(registryClient), WithOCIGetter(providers))
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(r).ToNot(BeNil())

			chart := "podinfo"
			cv, err := r.Get(chart, tc.version)
			if tc.expectedErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tc.expectedErr))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(cv.URLs[0]).To(Equal(fmt.Sprintf("%s/%s:%s", url, chart, tc.expected)))
			g.Expect(registryClient.LastCalledURL).To(Equal(fmt.Sprintf("%s/%s", strings.TrimPrefix(url, fmt.Sprintf("%s://", registry.OCIScheme)), chart)))
		})
	}
}

func TestOCIChartRepoisitory_DownloadChart(t *testing.T) {
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
