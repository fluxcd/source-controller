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
	"fmt"
	"io/ioutil"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"
)

// ChartRepository represents a Helm chart repository, and the configuration
// required to download the chart index, and charts from the repository.
type ChartRepository struct {
	URL     string
	Index   *repo.IndexFile
	Client  getter.Getter
	Options []getter.Option
}

// NewChartRepository constructs and returns a new ChartRepository with
// the ChartRepository.Client configured to the getter.Getter for the
// repository URL scheme. It returns an error on URL parsing failures,
// or if there is no getter available for the scheme.
func NewChartRepository(repositoryURL string, providers getter.Providers, opts []getter.Option) (*ChartRepository, error) {
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return nil, err
	}
	c, err := providers.ByScheme(u.Scheme)
	if err != nil {
		return nil, err
	}
	return &ChartRepository{
		URL:     repositoryURL,
		Client:  c,
		Options: opts,
	}, nil
}

// Get returns the repo.ChartVersion for the given name, the version is expected
// to be a semver.Constraints compatible string. If version is empty, the latest
// stable version will be returned and prerelease versions will be ignored.
func (r *ChartRepository) Get(name, version string) (*repo.ChartVersion, error) {
	cvs, ok := r.Index.Entries[name]
	if !ok {
		return nil, repo.ErrNoChartName
	}
	if len(cvs) == 0 {
		return nil, repo.ErrNoChartVersion
	}

	// Check for exact matches first
	if len(version) != 0 {
		for _, cv := range cvs {
			if version == cv.Version {
				return cv, nil
			}
		}
	}

	// Continue to look for a (semantic) version match
	latestStable := len(version) == 0 || version == "*"
	var match *semver.Constraints
	if !latestStable {
		rng, err := semver.NewConstraint(version)
		if err != nil {
			return nil, err
		}
		match = rng
	}
	var filteredVersions semver.Collection
	lookup := make(map[string]*repo.ChartVersion)
	for _, cv := range cvs {
		v, err := semver.NewVersion(cv.Version)
		if err != nil {
			continue
		}
		// NB: given the entries are already sorted in LoadIndex,
		// there is a high probability the first match would be
		// the right match to return. However, due to the fact that
		// we use a different semver package than Helm does, we still
		// need to sort it by our own rules.
		if match != nil && !match.Check(v) {
			continue
		}
		filteredVersions = append(filteredVersions, v)
		lookup[v.String()] = cv
	}
	if len(filteredVersions) == 0 {
		return nil, fmt.Errorf("no chart version found for %s-%s", name, version)
	}
	sort.Sort(sort.Reverse(filteredVersions))

	latest := filteredVersions[0]
	if latestStable {
		for _, v := range filteredVersions {
			if len(v.Prerelease()) == 0 {
				latest = v
				break
			}
		}
	}
	return lookup[latest.String()], nil
}

// DownloadChart confirms the given repo.ChartVersion has a downloadable URL,
// and then attempts to download the chart using the Client and Options of the
// ChartRepository. It returns a bytes.Buffer containing the chart data.
func (r *ChartRepository) DownloadChart(chart *repo.ChartVersion) (*bytes.Buffer, error) {
	if len(chart.URLs) == 0 {
		return nil, fmt.Errorf("chart %q has no downloadable URLs", chart.Name)
	}

	// TODO(hidde): according to the Helm source the first item is not
	//  always the correct one to pick, check for updates once in awhile.
	//  Ref: https://github.com/helm/helm/blob/v3.3.0/pkg/downloader/chart_downloader.go#L241
	ref := chart.URLs[0]
	u, err := url.Parse(ref)
	if err != nil {
		err = fmt.Errorf("invalid chart URL format '%s': %w", ref, err)
		return nil, err
	}

	// Prepend the chart repository base URL if the URL is relative
	if !u.IsAbs() {
		repoURL, err := url.Parse(r.URL)
		if err != nil {
			err = fmt.Errorf("invalid chart repository URL format '%s': %w", r.URL, err)
			return nil, err
		}
		q := repoURL.Query()
		// Trailing slash is required for ResolveReference to work
		repoURL.Path = strings.TrimSuffix(repoURL.Path, "/") + "/"
		u = repoURL.ResolveReference(u)
		u.RawQuery = q.Encode()
	}

	return r.Client.Get(u.String(), r.Options...)
}

// LoadIndex loads the given bytes into the Index while performing
// minimal validity checks. It fails if the API version is not set
// (repo.ErrNoAPIVersion), or if the unmarshal fails.
//
// The logic is derived from and on par with:
// https://github.com/helm/helm/blob/v3.3.4/pkg/repo/index.go#L301
func (r *ChartRepository) LoadIndex(b []byte) error {
	i := &repo.IndexFile{}
	if err := yaml.UnmarshalStrict(b, i); err != nil {
		return err
	}
	if i.APIVersion == "" {
		return repo.ErrNoAPIVersion
	}
	i.SortEntries()
	r.Index = i
	return nil
}

// DownloadIndex attempts to download the chart repository index using
// the Client and set Options, and loads the index file into the Index.
// It returns an error on URL parsing and Client failures.
func (r *ChartRepository) DownloadIndex() error {
	u, err := url.Parse(r.URL)
	if err != nil {
		return err
	}
	u.RawPath = path.Join(u.RawPath, "index.yaml")
	u.Path = path.Join(u.Path, "index.yaml")

	res, err := r.Client.Get(u.String(), r.Options...)
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(res)
	if err != nil {
		return err
	}

	return r.LoadIndex(b)
}
