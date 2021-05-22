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

package helm

import (
	"bytes"
	"crypto/sha1"
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

	"github.com/fluxcd/pkg/version"
)

// ChartRepository represents a Helm chart repository, and the configuration
// required to download the chart index, and charts from the repository.
type ChartRepository struct {
	URL      string
	Index    *repo.IndexFile
	Checksum string
	Client   getter.Getter
	Options  []getter.Option
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
func (r *ChartRepository) Get(name, ver string) (*repo.ChartVersion, error) {
	cvs, ok := r.Index.Entries[name]
	if !ok {
		return nil, repo.ErrNoChartName
	}
	if len(cvs) == 0 {
		return nil, repo.ErrNoChartVersion
	}

	// Check for exact matches first
	if len(ver) != 0 {
		for _, cv := range cvs {
			if ver == cv.Version {
				return cv, nil
			}
		}
	}

	// Continue to look for a (semantic) version match
	verConstraint, err := semver.NewConstraint("*")
	if err != nil {
		return nil, err
	}
	latestStable := len(ver) == 0 || ver == "*"
	if !latestStable {
		verConstraint, err = semver.NewConstraint(ver)
		if err != nil {
			return nil, err
		}
	}

	// Filter out chart versions that doesn't satisfy constraints if any,
	// parse semver and build a lookup table
	var matchedVersions semver.Collection
	lookup := make(map[*semver.Version]*repo.ChartVersion)
	for _, cv := range cvs {
		v, err := version.ParseVersion(cv.Version)
		if err != nil {
			continue
		}

		if !verConstraint.Check(v) {
			continue
		}

		matchedVersions = append(matchedVersions, v)
		lookup[v] = cv
	}
	if len(matchedVersions) == 0 {
		return nil, fmt.Errorf("no chart version found for %s-%s", name, ver)
	}

	// Sort versions
	sort.SliceStable(matchedVersions, func(i, j int) bool {
		// Reverse
		return !(func() bool {
			left := matchedVersions[i]
			right := matchedVersions[j]

			if !left.Equal(right) {
				return left.LessThan(right)
			}

			// Having chart creation timestamp at our disposal, we put package with the
			// same version into a chronological order. This is especially important for
			// versions that differ only by build metadata, because it is not considered
			// a part of the comparable version in Semver
			return lookup[left].Created.Before(lookup[right].Created)
		})()
	})

	latest := matchedVersions[0]
	return lookup[latest], nil
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
	r.Checksum = fmt.Sprintf("%x", sha1.Sum(b))
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
