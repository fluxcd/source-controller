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
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	helmgetter "helm.sh/helm/v4/pkg/getter"
	"helm.sh/helm/v4/pkg/registry"
	repo "helm.sh/helm/v4/pkg/repo/v1"

	"github.com/fluxcd/source-controller/internal/oci"
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

func (m *mockRegistryClient) Resolve(ref string) (ocispec.Descriptor, error) {
	m.LastCalledURL = ref
	return ocispec.Descriptor{Digest: digest.FromString(ref)}, nil
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
			expected: "localhost:5000/my_repo/podinfo:1.0.0",
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
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := NewWithT(t)

			u, err := url.Parse(tc.url)
			g.Expect(err).ToNot(HaveOccurred())

			mg := OCIMockGetter{}
			r := OCIChartRepository{
				Client: &mg,
				URL:    *u,
			}

			res, err := r.DownloadChart(tc.chartVersion)
			if tc.expectedErr {
				g.Expect(err).To(HaveOccurred())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(mg.LastCalledURL).To(Equal(tc.expected))
			g.Expect(res).ToNot(BeNil())
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

type mockChartVerifier struct {
	result      oci.VerificationResult
	err         error
	verifiedRef name.Reference
}

func (v *mockChartVerifier) Verify(_ context.Context, ref name.Reference) (oci.VerificationResult, error) {
	v.verifiedRef = ref
	return v.result, v.err
}

func TestOCIChartRepository_VerifyChart(t *testing.T) {
	g := NewWithT(t)

	u, err := url.Parse("oci://localhost:5000/my_repo")
	g.Expect(err).ToNot(HaveOccurred())

	chartRef := "oci://localhost:5000/my_repo/podinfo:1.0.0"
	// The digest the mock registry client resolves the tag to.
	resolvedDigest := digest.FromString("localhost:5000/my_repo/podinfo:1.0.0")
	pinnedRef := fmt.Sprintf("oci://localhost:5000/my_repo/podinfo@%s", resolvedDigest)

	t.Run("verifies the resolved digest and pins the chart URL to it", func(t *testing.T) {
		g := NewWithT(t)

		verifier := &mockChartVerifier{result: oci.VerificationResultSuccess}
		r := OCIChartRepository{
			URL:            *u,
			RegistryClient: &mockRegistryClient{},
			verifiers:      []oci.Verifier{verifier},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{chartRef},
		}
		result, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(result).To(Equal(oci.VerificationResultSuccess))
		g.Expect(verifier.verifiedRef.String()).To(Equal(fmt.Sprintf("localhost:5000/my_repo/podinfo@%s", resolvedDigest)))
		g.Expect(cv.URLs[0]).To(Equal(pinnedRef))
	})

	t.Run("fails when the digest can not be resolved", func(t *testing.T) {
		g := NewWithT(t)

		r := OCIChartRepository{
			URL:            *u,
			RegistryClient: &mockRegistryClientResolveErr{},
			verifiers:      []oci.Verifier{&mockChartVerifier{result: oci.VerificationResultSuccess}},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{chartRef},
		}
		result, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("failed to resolve digest"))
		g.Expect(result).To(Equal(oci.VerificationResultFailed))
		g.Expect(cv.URLs[0]).To(Equal(chartRef))
	})

	t.Run("fails on an invalid resolved digest", func(t *testing.T) {
		g := NewWithT(t)

		r := OCIChartRepository{
			URL:            *u,
			RegistryClient: &mockRegistryClientInvalidDigest{},
			verifiers:      []oci.Verifier{&mockChartVerifier{result: oci.VerificationResultSuccess}},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{chartRef},
		}
		result, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("invalid digest"))
		g.Expect(result).To(Equal(oci.VerificationResultFailed))
		g.Expect(cv.URLs[0]).To(Equal(chartRef))
	})

	t.Run("keeps an already pinned digest reference", func(t *testing.T) {
		g := NewWithT(t)

		verifier := &mockChartVerifier{result: oci.VerificationResultSuccess}
		r := OCIChartRepository{
			URL:            *u,
			RegistryClient: &mockRegistryClientFixedDigest{dig: resolvedDigest},
			verifiers:      []oci.Verifier{verifier},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{pinnedRef},
		}
		result, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(result).To(Equal(oci.VerificationResultSuccess))
		g.Expect(cv.URLs[0]).To(Equal(pinnedRef))
	})

	t.Run("pins the chart URL when the result is ignored", func(t *testing.T) {
		g := NewWithT(t)

		r := OCIChartRepository{
			URL:            *u,
			RegistryClient: &mockRegistryClient{},
			verifiers:      []oci.Verifier{&mockChartVerifier{result: oci.VerificationResultIgnored}},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{chartRef},
		}
		result, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(result).To(Equal(oci.VerificationResultIgnored))
		g.Expect(cv.URLs[0]).To(Equal(pinnedRef))
	})

	t.Run("downloads the reference that was verified", func(t *testing.T) {
		g := NewWithT(t)

		mg := OCIMockGetter{}
		r := OCIChartRepository{
			URL:            *u,
			Client:         &mg,
			RegistryClient: &mockRegistryClient{},
			verifiers:      []oci.Verifier{&mockChartVerifier{result: oci.VerificationResultSuccess}},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{chartRef},
		}
		_, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).ToNot(HaveOccurred())

		_, err = r.DownloadChart(cv)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(mg.LastCalledURL).To(Equal(fmt.Sprintf("localhost:5000/my_repo/podinfo@%s", resolvedDigest)))
	})

	t.Run("fails without verifiers", func(t *testing.T) {
		g := NewWithT(t)

		r := OCIChartRepository{
			URL:            *u,
			RegistryClient: &mockRegistryClient{},
		}

		cv := &repo.ChartVersion{
			Metadata: &chart.Metadata{Name: "podinfo", Version: "1.0.0"},
			URLs:     []string{chartRef},
		}
		result, err := r.VerifyChart(t.Context(), cv)
		g.Expect(err).To(HaveOccurred())
		g.Expect(result).To(Equal(oci.VerificationResultFailed))
	})
}

type mockRegistryClientInvalidDigest struct {
	mockRegistryClient
}

func (m *mockRegistryClientInvalidDigest) Resolve(ref string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}

type mockRegistryClientFixedDigest struct {
	mockRegistryClient
	dig digest.Digest
}

func (m *mockRegistryClientFixedDigest) Resolve(ref string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{Digest: m.dig}, nil
}

type mockRegistryClientResolveErr struct {
	mockRegistryClient
}

func (m *mockRegistryClientResolveErr) Resolve(ref string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, fmt.Errorf("manifest unknown")
}
