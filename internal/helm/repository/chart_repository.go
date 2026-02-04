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
	"context"
	"crypto/tls"
	"encoding/json"
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
	"github.com/opencontainers/go-digest"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/version"

	"github.com/fluxcd/pkg/http/transport"
	"github.com/werf/nelm-source-controller/internal/helm"
	"github.com/werf/nelm-source-controller/internal/oci"
)

var (
	ErrNoChartIndex = errors.New("no chart index")
)

// IndexFromFile loads a repo.IndexFile from the given path. It returns an
// error if the file does not exist, is not a regular file, exceeds the
// maximum index file size, or if the file cannot be parsed.
func IndexFromFile(path string) (*repo.IndexFile, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > helm.MaxIndexSize {
		return nil, fmt.Errorf("%s exceeds the maximum index file size of %d bytes", path, helm.MaxIndexSize)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return IndexFromBytes(b)
}

// IndexFromBytes loads a repo.IndexFile from the given bytes. It returns an
// error if the bytes cannot be parsed, or if the API version is not set.
// The entries are sorted before the index is returned.
func IndexFromBytes(b []byte) (*repo.IndexFile, error) {
	if len(b) == 0 {
		return nil, repo.ErrEmptyIndexYaml
	}

	i := &repo.IndexFile{}
	if err := jsonOrYamlUnmarshal(b, i); err != nil {
		return nil, err
	}

	if i.APIVersion == "" {
		return nil, repo.ErrNoAPIVersion
	}

	for name, cvs := range i.Entries {
		for idx := len(cvs) - 1; idx >= 0; idx-- {
			if cvs[idx] == nil {
				continue
			}
			// When metadata section missing, initialize with no data
			if cvs[idx].Metadata == nil {
				cvs[idx].Metadata = &chart.Metadata{}
			}
			if cvs[idx].APIVersion == "" {
				cvs[idx].APIVersion = chart.APIVersionV1
			}
			if err := cvs[idx].Validate(); ignoreSkippableChartValidationError(err) != nil {
				cvs = append(cvs[:idx], cvs[idx+1:]...)
			}
		}
		// adjust slice to only contain a set of valid versions
		i.Entries[name] = cvs
	}

	i.SortEntries()
	return i, nil
}

// ChartRepository represents a Helm chart repository, and the configuration
// required to download the chart index and charts from the repository.
// All methods are thread safe unless defined otherwise.
type ChartRepository struct {
	// URL the ChartRepository's index.yaml can be found at,
	// without the index.yaml suffix.
	URL string
	// Path is the absolute path to the Index file.
	Path string
	// Index of the ChartRepository.
	Index *repo.IndexFile

	// Client to use while downloading the Index or a chart from the URL.
	Client getter.Getter
	// Options to configure the Client with while downloading the Index
	// or a chart from the URL.
	Options []getter.Option

	tlsConfig *tls.Config

	cached  bool
	digests map[digest.Algorithm]digest.Digest

	*sync.RWMutex
}

// NewChartRepository constructs and returns a new ChartRepository with
// the ChartRepository.Client configured to the getter.Getter for the
// repository URL scheme. It returns an error on URL parsing failures,
// or if there is no getter available for the scheme.
func NewChartRepository(URL, path string, providers getter.Providers, tlsConfig *tls.Config, getterOpts ...getter.Option) (*ChartRepository, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	c, err := providers.ByScheme(u.Scheme)
	if err != nil {
		return nil, err
	}

	r := newChartRepository()
	r.URL = URL
	r.Path = path
	r.Client = c
	r.Options = getterOpts
	r.tlsConfig = tlsConfig

	return r, nil
}

func newChartRepository() *ChartRepository {
	return &ChartRepository{
		digests: make(map[digest.Algorithm]digest.Digest, 0),
		RWMutex: &sync.RWMutex{},
	}
}

// GetChartVersion returns the repo.ChartVersion for the given name, the version is expected
// to be a semver.Constraints compatible string. If version is empty, the latest
// stable version will be returned and prerelease versions will be ignored.
func (r *ChartRepository) GetChartVersion(name, ver string) (*repo.ChartVersion, error) {
	// See if we already have the index in cache or try to load it.
	if err := r.StrategicallyLoadIndex(); err != nil {
		return nil, &ErrExternal{Err: err}
	}

	cv, err := r.getChartVersion(name, ver)
	if err != nil {
		return nil, &ErrReference{Err: err}
	}
	return cv, nil
}

func (r *ChartRepository) getChartVersion(name, ver string) (*repo.ChartVersion, error) {
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

	// Filter out chart versions that don't satisfy constraints if any,
	// parse semver and build a lookup table
	var matchedVersions semver.Collection
	lookup := make(map[*semver.Version]*repo.ChartVersion, 0)
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
	resolvedUrl, err := repo.ResolveReferenceURL(r.URL, ref)
	if err != nil {
		return nil, err
	}

	t := transport.NewOrIdle(r.tlsConfig)
	clientOpts := append(r.Options, getter.WithTransport(t))
	defer transport.Release(t)

	return r.Client.Get(resolvedUrl, clientOpts...)
}

// CacheIndex attempts to write the index from the remote into a new temporary file
// using DownloadIndex, and sets Path and cached.
// The caller is expected to handle the garbage collection of Path, and to
// load the Index separately using LoadFromPath if required.
func (r *ChartRepository) CacheIndex() error {
	f, err := os.CreateTemp("", "chart-index-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file to cache index to: %w", err)
	}

	if err = r.DownloadIndex(f, helm.MaxIndexSize); err != nil {
		f.Close()
		removeErr := os.Remove(f.Name())
		if removeErr != nil {
			err = errors.Join(err, removeErr)
		}
		return fmt.Errorf("failed to cache index to temporary file: %w", err)
	}

	if err = f.Close(); err != nil {
		removeErr := os.Remove(f.Name())
		if removeErr != nil {
			err = errors.Join(err, removeErr)
		}
		return fmt.Errorf("failed to close cached index file '%s': %w", f.Name(), err)
	}

	r.Lock()
	r.Path = f.Name()
	r.Index = nil
	r.cached = true
	r.invalidate()
	r.Unlock()

	return nil
}

// StrategicallyLoadIndex lazy-loads the Index if required, first
// attempting to load it from Path if the file exists, before falling
// back to caching it.
func (r *ChartRepository) StrategicallyLoadIndex() (err error) {
	if r.HasIndex() {
		return
	}

	if !r.HasFile() {
		if err = r.CacheIndex(); err != nil {
			err = fmt.Errorf("failed to cache index: %w", err)
			return
		}
	}

	if err = r.LoadFromPath(); err != nil {
		err = fmt.Errorf("failed to load index: %w", err)
		return
	}
	return
}

// LoadFromPath attempts to load the Index from the configured Path.
// It returns an error if no Path is set, or if the load failed.
func (r *ChartRepository) LoadFromPath() error {
	r.Lock()
	defer r.Unlock()

	if len(r.Path) == 0 {
		return fmt.Errorf("no cache path")
	}

	i, err := IndexFromFile(r.Path)
	if err != nil {
		return fmt.Errorf("failed to load index: %w", err)
	}

	r.Index = i
	return nil
}

// DownloadIndex attempts to download the chart repository index using
// the Client and set Options, and writes the index to the given io.Writer.
// Upon download, the index is copied to the writer if the index size
// does not exceed the maximum index file size. Otherwise, it returns an error.
// A url.Error is returned if the URL failed to parse.
func (r *ChartRepository) DownloadIndex(w io.Writer, maxSize int64) (err error) {
	r.RLock()
	defer r.RUnlock()

	u, err := url.Parse(r.URL)
	if err != nil {
		return err
	}
	u.RawPath = path.Join(u.RawPath, "index.yaml")
	u.Path = path.Join(u.Path, "index.yaml")

	t := transport.NewOrIdle(r.tlsConfig)
	clientOpts := append(r.Options, getter.WithTransport(t))
	defer transport.Release(t)

	var res *bytes.Buffer
	res, err = r.Client.Get(u.String(), clientOpts...)
	if err != nil {
		return err
	}

	if int64(res.Len()) > maxSize {
		return fmt.Errorf("index exceeds the maximum index file size of %d bytes", maxSize)
	}

	if _, err = io.Copy(w, res); err != nil {
		return err
	}
	return nil
}

// Digest returns the digest of the file at the ChartRepository's Path.
func (r *ChartRepository) Digest(algorithm digest.Algorithm) digest.Digest {
	if !r.HasFile() {
		return ""
	}

	r.Lock()
	defer r.Unlock()

	if _, ok := r.digests[algorithm]; !ok {
		if f, err := os.Open(r.Path); err == nil {
			defer f.Close()
			rd := io.LimitReader(f, helm.MaxIndexSize)
			if d, err := algorithm.FromReader(rd); err == nil {
				r.digests[algorithm] = d
			}
		}
	}
	return r.digests[algorithm]
}

// ToJSON returns the index formatted as JSON.
func (r *ChartRepository) ToJSON() ([]byte, error) {
	if !r.HasIndex() {
		return nil, fmt.Errorf("index not loaded yet")
	}

	return json.MarshalIndent(r.Index, "", "  ")
}

// HasIndex returns true if the Index is not nil.
func (r *ChartRepository) HasIndex() bool {
	r.RLock()
	defer r.RUnlock()

	return r.Index != nil
}

// HasFile returns true if Path exists and is a regular file.
func (r *ChartRepository) HasFile() bool {
	r.RLock()
	defer r.RUnlock()

	if r.Path != "" {
		if stat, err := os.Lstat(r.Path); err == nil {
			return stat.Mode().IsRegular()
		}
	}
	return false
}

// Clear clears the Index and removes the file at Path, if cached.
func (r *ChartRepository) Clear() error {
	r.Lock()
	defer r.Unlock()

	r.Index = nil

	if r.cached {
		if err := os.Remove(r.Path); err != nil {
			return fmt.Errorf("failed to remove cached index: %w", err)
		}
		r.Path = ""
		r.cached = false
	}

	r.invalidate()
	return nil
}

// Invalidate clears any cached digests.
func (r *ChartRepository) Invalidate() {
	r.Lock()
	defer r.Unlock()

	r.invalidate()
}

func (r *ChartRepository) invalidate() {
	r.digests = make(map[digest.Algorithm]digest.Digest, 0)
}

// VerifyChart verifies the chart against a signature.
// It returns an error on failure.
func (r *ChartRepository) VerifyChart(_ context.Context, _ *repo.ChartVersion) (oci.VerificationResult, error) {
	// this is a no-op because this is not implemented yet.
	return oci.VerificationResultIgnored, fmt.Errorf("not implemented")
}

// jsonOrYamlUnmarshal unmarshals the given byte slice containing JSON or YAML
// into the provided interface.
//
// It automatically detects whether the data is in JSON or YAML format by
// checking its validity as JSON. If the data is valid JSON, it will use the
// `encoding/json` package to unmarshal it. Otherwise, it will use the
// `sigs.k8s.io/yaml` package to unmarshal the YAML data.
//
// Can potentially be replaced when Helm PR for JSON support has been merged.
// xref: https://github.com/helm/helm/pull/12245
func jsonOrYamlUnmarshal(b []byte, i interface{}) error {
	if json.Valid(b) {
		return json.Unmarshal(b, i)
	}
	return yaml.UnmarshalStrict(b, i)
}

// ignoreSkippableChartValidationError inspect the given error and returns nil if
// the error isn't important for index loading
//
// In particular, charts may introduce validations that don't impact repository indexes
// And repository indexes may be generated by older/non-complient software, which doesn't
// conform to all validations.
//
// this code is taken from https://github.com/helm/helm/blob/v3.15.2/pkg/repo/index.go#L402
func ignoreSkippableChartValidationError(err error) error {
	verr, ok := err.(chart.ValidationError)
	if !ok {
		return err
	}

	// https://github.com/helm/helm/issues/12748 (JFrog repository strips alias field from index)
	if strings.HasPrefix(verr.Error(), "validation: more than one dependency with name or alias") {
		return nil
	}

	return err
}
