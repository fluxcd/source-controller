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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/version"

	"github.com/fluxcd/source-controller/internal/helm"
)

var ErrNoChartIndex = errors.New("no chart index")

// ChartRepository represents a Helm chart repository, and the configuration
// required to download the chart index and charts from the repository.
// All methods are thread safe unless defined otherwise.
type ChartRepository struct {
	// URL the ChartRepository's index.yaml can be found at,
	// without the index.yaml suffix.
	URL string
	// Client to use while downloading the Index or a chart from the URL.
	Client getter.Getter
	// Options to configure the Client with while downloading the Index
	// or a chart from the URL.
	Options []getter.Option
	// CachePath is the path of a cached index.yaml for read-only operations.
	CachePath string
	// Cached indicates if the ChartRepository index.yaml has been cached
	// to CachePath.
	Cached bool
	// Index contains a loaded chart repository index if not nil.
	Index *repo.IndexFile
	// Checksum contains the SHA256 checksum of the loaded chart repository
	// index bytes.
	Checksum string

	*sync.RWMutex
}

// NewChartRepository constructs and returns a new ChartRepository with
// the ChartRepository.Client configured to the getter.Getter for the
// repository URL scheme. It returns an error on URL parsing failures,
// or if there is no getter available for the scheme.
func NewChartRepository(repositoryURL, cachePath string, providers getter.Providers, opts []getter.Option) (*ChartRepository, error) {
	u, err := url.Parse(repositoryURL)
	if err != nil {
		return nil, err
	}
	c, err := providers.ByScheme(u.Scheme)
	if err != nil {
		return nil, err
	}

	r := newChartRepository()
	r.URL = repositoryURL
	r.CachePath = cachePath
	r.Client = c
	r.Options = opts
	return r, nil
}

func newChartRepository() *ChartRepository {
	return &ChartRepository{
		RWMutex: &sync.RWMutex{},
	}
}

// Get returns the repo.ChartVersion for the given name, the version is expected
// to be a semver.Constraints compatible string. If version is empty, the latest
// stable version will be returned and prerelease versions will be ignored.
func (r *ChartRepository) Get(name, ver string) (*repo.ChartVersion, error) {
	r.RLock()
	defer r.RUnlock()

	if r.Index == nil {
		return nil, ErrNoChartIndex
	}
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
		return nil, fmt.Errorf("no '%s' chart with version matching '%s' found", name, ver)
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
		return nil, fmt.Errorf("chart '%s' has no downloadable URLs", chart.Name)
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

// LoadIndexFromBytes loads Index from the given bytes.
// It returns a repo.ErrNoAPIVersion error if the API version is not set
func (r *ChartRepository) LoadIndexFromBytes(b []byte) error {
	i := &repo.IndexFile{}
	if err := yaml.UnmarshalStrict(b, i); err != nil {
		return err
	}
	if i.APIVersion == "" {
		return repo.ErrNoAPIVersion
	}
	i.SortEntries()

	r.Lock()
	r.Index = i
	r.Checksum = fmt.Sprintf("%x", sha256.Sum256(b))
	r.Unlock()
	return nil
}

// LoadFromFile reads the file at the given path and loads it into Index.
func (r *ChartRepository) LoadFromFile(path string) error {
	stat, err := os.Stat(path)
	if err != nil || stat.IsDir() {
		if err == nil {
			err = fmt.Errorf("'%s' is a directory", path)
		}
		return err
	}
	if stat.Size() > helm.MaxIndexSize {
		return fmt.Errorf("size of index '%s' exceeds '%d' bytes limit", stat.Name(), helm.MaxIndexSize)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return r.LoadIndexFromBytes(b)
}

// CacheIndex attempts to write the index from the remote into a new temporary file
// using DownloadIndex, and sets CachePath and Cached.
// It returns the SHA256 checksum of the downloaded index bytes, or an error.
// The caller is expected to handle the garbage collection of CachePath, and to
// load the Index separately using LoadFromCache if required.
func (r *ChartRepository) CacheIndex() (string, error) {
	f, err := os.CreateTemp("", "chart-index-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file to cache index to: %w", err)
	}

	h := sha256.New()
	mw := io.MultiWriter(f, h)
	if err = r.DownloadIndex(mw); err != nil {
		f.Close()
		os.RemoveAll(f.Name())
		return "", fmt.Errorf("failed to cache index to temporary file: %w", err)
	}
	if err = f.Close(); err != nil {
		os.RemoveAll(f.Name())
		return "", fmt.Errorf("failed to close cached index file '%s': %w", f.Name(), err)
	}

	r.Lock()
	r.CachePath = f.Name()
	r.Cached = true
	r.Unlock()
	return hex.EncodeToString(h.Sum(nil)), nil
}

// StrategicallyLoadIndex lazy-loads the Index from CachePath using
// LoadFromCache if it does not HasIndex.
// If not HasCacheFile, a cache attempt is made using CacheIndex
// before continuing to load.
func (r *ChartRepository) StrategicallyLoadIndex() (err error) {
	if r.HasIndex() {
		return
	}
	if !r.HasCacheFile() {
		if _, err = r.CacheIndex(); err != nil {
			err = fmt.Errorf("failed to strategically load index: %w", err)
			return
		}
	}
	if err = r.LoadFromCache(); err != nil {
		err = fmt.Errorf("failed to strategically load index: %w", err)
		return
	}
	return
}

// LoadFromCache attempts to load the Index from the configured CachePath.
// It returns an error if no CachePath is set, or if the load failed.
func (r *ChartRepository) LoadFromCache() error {
	if cachePath := r.CachePath; cachePath != "" {
		return r.LoadFromFile(cachePath)
	}
	return fmt.Errorf("no cache path set")
}

// DownloadIndex attempts to download the chart repository index using
// the Client and set Options, and writes the index to the given io.Writer.
// It returns an url.Error if the URL failed to parse.
func (r *ChartRepository) DownloadIndex(w io.Writer) (err error) {
	u, err := url.Parse(r.URL)
	if err != nil {
		return err
	}
	u.RawPath = path.Join(u.RawPath, "index.yaml")
	u.Path = path.Join(u.Path, "index.yaml")

	var res *bytes.Buffer
	res, err = r.Client.Get(u.String(), r.Options...)
	if err != nil {
		return err
	}
	if _, err = io.Copy(w, res); err != nil {
		return err
	}
	return nil
}

// HasIndex returns true if the Index is not nil.
func (r *ChartRepository) HasIndex() bool {
	r.RLock()
	defer r.RUnlock()
	return r.Index != nil
}

// HasCacheFile returns true if CachePath is not empty.
func (r *ChartRepository) HasCacheFile() bool {
	r.RLock()
	defer r.RUnlock()
	return r.CachePath != ""
}

// Unload can be used to signal the Go garbage collector the Index can
// be freed from memory if the ChartRepository object is expected to
// continue to exist in the stack for some time.
func (r *ChartRepository) Unload() {
	if r == nil {
		return
	}

	r.Lock()
	defer r.Unlock()
	r.Index = nil
}

// RemoveCache removes the CachePath if Cached.
func (r *ChartRepository) RemoveCache() error {
	if r == nil {
		return nil
	}

	r.Lock()
	defer r.Unlock()

	if r.Cached {
		if err := os.Remove(r.CachePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		r.CachePath = ""
		r.Cached = false
	}
	return nil
}
