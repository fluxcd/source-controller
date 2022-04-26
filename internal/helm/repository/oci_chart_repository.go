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
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/fluxcd/source-controller/internal/transport"
)

// ChartRepository represents a Helm chart repository, and the configuration
// required to download the chart index and charts from the repository.
// All methods are thread safe unless defined otherwise.
type OCIChartRepository struct {
	// URL the ChartRepository's index.yaml can be found at,
	// without the index.yaml suffix.
	URL string
	// Client to use while downloading the Index or a chart from the URL.
	Client getter.Getter
	// Options to configure the Client with while downloading the Index
	// or a chart from the URL.
	Options []getter.Option

	tlsConfig *tls.Config

	// RegistryClient is a client to use while downloading tags or charts from a registry.
	RegistryClient *registry.Client
}

// NewChartRepository constructs and returns a new ChartRepository with
// the ChartRepository.Client configured to the getter.Getter for the
// repository URL scheme. It returns an error on URL parsing failures,
// or if there is no getter available for the scheme.
func NewOCIChartRepository(repositoryURL, cachePath string, providers getter.Providers, tlsConfig *tls.Config, getterOpts []getter.Option) (*OCIChartRepository, error) {
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return nil, err
	}

	if !registry.IsOCI(repositoryURL) {
		return nil, fmt.Errorf("the url scheme is not supported: %s", u.Scheme)
	}
	c, err := providers.ByScheme(u.Scheme)
	if err != nil {
		return nil, err
	}

	r := newOCIChartRepository()
	r.URL = repositoryURL
	r.Client = c
	r.Options = getterOpts
	r.tlsConfig = tlsConfig

	return r, nil
}

func newOCIChartRepository() *OCIChartRepository {
	return &OCIChartRepository{}
}

// Get returns the repo.ChartVersion for the given name, the version is expected
// to be a semver.Constraints compatible string. If version is empty, the latest
// stable version will be returned and prerelease versions will be ignored.
// copy of https://github.com/helm/helm/blob/49819b4ef782e80b0c7f78c30bd76b51ebb56dc8/pkg/downloader/chart_downloader.go#L162
func (r *OCIChartRepository) Get(name, ver string) (string, error) {
	// Find chart versions matching the given name.
	// Either in an index file or from a registry.
	cvs, err := r.getTags(fmt.Sprintf("%s/%s", r.URL, name))
	if err != nil {
		return "", err
	}

	if len(cvs) == 0 {
		return "", fmt.Errorf("unable to locate any tags in provided repository: %s", name)
	}

	// Determine if version provided
	// If empty, try to get the highest available tag
	// If exact version, try to find it
	// If semver constraint string, try to find a match
	tag, err := registry.GetTagMatchingVersionOrConstraint(cvs, ver)
	return tag, err
}

// this function shall be called for OCI registries only
// It assumes that the ref has been validated to be an OCI reference.
func (r *OCIChartRepository) getTags(ref string) ([]string, error) {
	// Retrieve list of repository tags
	tags, err := r.RegistryClient.Tags(strings.TrimPrefix(ref, fmt.Sprintf("%s://", registry.OCIScheme)))
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("unable to locate any tags in provided repository: %s", ref)
	}

	return tags, nil
}

// DownloadChart confirms the given repo.ChartVersion has a downloadable URL,
// and then attempts to download the chart using the Client and Options of the
// ChartRepository. It returns a bytes.Buffer containing the chart data.
// In case of an OCI hosted chart, this function assumes that the chartVersion url is valid.
func (r *OCIChartRepository) DownloadChart(chart *repo.ChartVersion) (*bytes.Buffer, error) {
	if len(chart.URLs) == 0 {
		return nil, fmt.Errorf("chart '%s' has no downloadable URLs", chart.Name)
	}

	ref := chart.URLs[0]
	u, err := url.Parse(ref)
	if err != nil {
		err = fmt.Errorf("invalid chart URL format '%s': %w", ref, err)
		return nil, err
	}

	t := transport.NewOrIdle(r.tlsConfig)
	clientOpts := append(r.Options, getter.WithTransport(t))
	defer transport.Release(t)

	// trim the oci scheme prefix if needed
	return r.Client.Get(strings.TrimPrefix(u.String(), registry.OCIScheme), clientOpts...)
}
