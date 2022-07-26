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
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"

	"github.com/Masterminds/semver/v3"
	"github.com/fluxcd/pkg/version"
	"github.com/fluxcd/source-controller/internal/transport"
)

// RegistryClient is an interface for interacting with OCI registries
// It is used by the OCIChartRepository to retrieve chart versions
// from OCI registries
type RegistryClient interface {
	Login(host string, opts ...registry.LoginOption) error
	Logout(host string, opts ...registry.LogoutOption) error
	Tags(url string) ([]string, error)
}

// OCIChartRepository represents a Helm chart repository, and the configuration
// required to download the repository tags and charts from the repository.
// All methods are thread safe unless defined otherwise.
type OCIChartRepository struct {
	// URL is the location of the repository.
	URL url.URL
	// Client to use while accessing the repository's contents.
	Client getter.Getter
	// Options to configure the Client with while downloading tags
	// or a chart from the URL.
	Options []getter.Option

	tlsConfig *tls.Config

	// RegistryClient is a client to use while downloading tags or charts from a registry.
	RegistryClient RegistryClient
	// credentialsFile is a temporary credentials file to use while downloading tags or charts from a registry.
	credentialsFile string
}

// OCIChartRepositoryOption is a function that can be passed to NewOCIChartRepository
// to configure an OCIChartRepository.
type OCIChartRepositoryOption func(*OCIChartRepository) error

// WithOCIRegistryClient returns a ChartRepositoryOption that will set the registry client
func WithOCIRegistryClient(client RegistryClient) OCIChartRepositoryOption {
	return func(r *OCIChartRepository) error {
		r.RegistryClient = client
		return nil
	}
}

// WithOCIGetter returns a ChartRepositoryOption that will set the getter.Getter
func WithOCIGetter(providers getter.Providers) OCIChartRepositoryOption {
	return func(r *OCIChartRepository) error {
		c, err := providers.ByScheme(r.URL.Scheme)
		if err != nil {
			return err
		}
		r.Client = c
		return nil
	}
}

// WithOCIGetterOptions returns a ChartRepositoryOption that will set the getter.Options
func WithOCIGetterOptions(getterOpts []getter.Option) OCIChartRepositoryOption {
	return func(r *OCIChartRepository) error {
		r.Options = getterOpts
		return nil
	}
}

// WithCredentialsFile returns a ChartRepositoryOption that will set the credentials file
func WithCredentialsFile(credentialsFile string) OCIChartRepositoryOption {
	return func(r *OCIChartRepository) error {
		r.credentialsFile = credentialsFile
		return nil
	}
}

// NewOCIChartRepository constructs and returns a new ChartRepository with
// the ChartRepository.Client configured to the getter.Getter for the
// repository URL scheme. It returns an error on URL parsing failures.
// It assumes that the url scheme has been validated to be an OCI scheme.
func NewOCIChartRepository(repositoryURL string, chartRepoOpts ...OCIChartRepositoryOption) (*OCIChartRepository, error) {
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return nil, err
	}

	r := &OCIChartRepository{}
	r.URL = *u
	for _, opt := range chartRepoOpts {
		if err := opt(r); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// GetChartVersion returns the repo.ChartVersion for the given name, the version is expected
// to be a semver.Constraints compatible string. If version is empty, the latest
// stable version will be returned and prerelease versions will be ignored.
// adapted from https://github.com/helm/helm/blob/49819b4ef782e80b0c7f78c30bd76b51ebb56dc8/pkg/downloader/chart_downloader.go#L162
func (r *OCIChartRepository) GetChartVersion(name, ver string) (*repo.ChartVersion, error) {

	cpURL := r.URL
	cpURL.Path = path.Join(cpURL.Path, name)

	// if ver is a valid semver version, take a shortcut here so we don't need to list all tags which can be an
	// expensive operation.
	if _, err := version.ParseVersion(ver); err == nil {
		return &repo.ChartVersion{
			URLs: []string{fmt.Sprintf("%s:%s", cpURL.String(), ver)},
			Metadata: &chart.Metadata{
				Name:    name,
				Version: ver,
			},
		}, nil
	}

	// ver doesn't denote a concrete version so we interpret it as a semver range and try to find the best-matching
	// version from the list of tags in the registry.

	cvs, err := r.getTags(cpURL.String())
	if err != nil {
		return nil, fmt.Errorf("could not get tags for %q: %s", name, err)
	}

	if len(cvs) == 0 {
		return nil, fmt.Errorf("unable to locate any tags in provided repository: %s", name)
	}

	// Determine if version provided
	// If empty, try to get the highest available tag
	// If exact version, try to find it
	// If semver constraint string, try to find a match
	tag, err := getLastMatchingVersionOrConstraint(cvs, ver)
	return &repo.ChartVersion{
		URLs: []string{fmt.Sprintf("%s:%s", cpURL.String(), tag)},
		Metadata: &chart.Metadata{
			Name:    name,
			Version: tag,
		},
	}, err
}

// This function shall be called for OCI registries only
// It assumes that the ref has been validated to be an OCI reference.
func (r *OCIChartRepository) getTags(ref string) ([]string, error) {
	// Retrieve list of repository tags
	tags, err := r.RegistryClient.Tags(strings.TrimPrefix(ref, fmt.Sprintf("%s://", registry.OCIScheme)))
	if err != nil {
		return nil, fmt.Errorf("could not fetch tags for %q: %s", ref, err)
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
	return r.Client.Get(strings.TrimPrefix(u.String(), fmt.Sprintf("%s://", registry.OCIScheme)), clientOpts...)
}

// Login attempts to login to the OCI registry.
// It returns an error on failure.
func (r *OCIChartRepository) Login(opts ...registry.LoginOption) error {
	err := r.RegistryClient.Login(r.URL.Host, opts...)
	if err != nil {
		return err
	}
	return nil
}

// Logout attempts to logout from the OCI registry.
// It returns an error on failure.
func (r *OCIChartRepository) Logout() error {
	err := r.RegistryClient.Logout(r.URL.Host)
	if err != nil {
		return err
	}
	return nil
}

// HasCredentials returns true if the OCIChartRepository has credentials.
func (r *OCIChartRepository) HasCredentials() bool {
	return r.credentialsFile != ""
}

// Clear deletes the OCI registry credentials file.
func (r *OCIChartRepository) Clear() error {
	// clean the credentials file if it exists
	if r.credentialsFile != "" {
		if err := os.Remove(r.credentialsFile); err != nil {
			return err
		}
	}
	r.credentialsFile = ""
	return nil
}

// getLastMatchingVersionOrConstraint returns the last version that matches the given version string.
// If the version string is empty, the highest available version is returned.
func getLastMatchingVersionOrConstraint(cvs []string, ver string) (string, error) {
	// Check for exact matches first
	if ver != "" {
		for _, cv := range cvs {
			if ver == cv {
				return cv, nil
			}
		}
	}

	// Continue to look for a (semantic) version match
	verConstraint, err := semver.NewConstraint("*")
	if err != nil {
		return "", err
	}
	latestStable := ver == "" || ver == "*"
	if !latestStable {
		verConstraint, err = semver.NewConstraint(ver)
		if err != nil {
			return "", err
		}
	}

	matchingVersions := make([]*semver.Version, 0, len(cvs))
	for _, cv := range cvs {
		v, err := version.ParseVersion(cv)
		if err != nil {
			continue
		}

		if !verConstraint.Check(v) {
			continue
		}

		matchingVersions = append(matchingVersions, v)
	}
	if len(matchingVersions) == 0 {
		return "", fmt.Errorf("could not locate a version matching provided version string %s", ver)
	}

	// Sort versions
	sort.Sort(sort.Reverse(semver.Collection(matchingVersions)))

	return matchingVersions[0].Original(), nil
}
