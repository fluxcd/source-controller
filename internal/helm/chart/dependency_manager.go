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

package chart

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"k8s.io/apimachinery/pkg/util/errors"

	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader"
	"github.com/fluxcd/source-controller/internal/helm/repository"
)

// GetChartDownloaderCallback must return a Downloader for the
// URL or an error describing why it could not be returned.
type GetChartDownloaderCallback func(url string) (repository.Downloader, error)

// DependencyManager manages dependencies for a Helm chart.
type DependencyManager struct {
	// downloaders contains a map of Downloader objects
	// indexed by their repository.NormalizeURL.
	// It is consulted as a lookup table for missing dependencies, based on
	// the (repository) URL the dependency refers to.
	downloaders map[string]repository.Downloader

	// getChartDownloaderCallback can be set to an on-demand GetChartDownloaderCallback
	// whose returned result is cached to downloaders.
	getChartDownloaderCallback GetChartDownloaderCallback

	// concurrent is the number of concurrent chart-add operations during
	// Build. Defaults to 1 (non-concurrent).
	concurrent int64

	// mu contains the lock for chart writes.
	mu sync.Mutex
}

// DependencyManagerOption configures an option on a DependencyManager.
type DependencyManagerOption interface {
	applyToDependencyManager(dm *DependencyManager)
}

type WithRepositories map[string]repository.Downloader

func (o WithRepositories) applyToDependencyManager(dm *DependencyManager) {
	dm.downloaders = o
}

type WithDownloaderCallback GetChartDownloaderCallback

func (o WithDownloaderCallback) applyToDependencyManager(dm *DependencyManager) {
	dm.getChartDownloaderCallback = GetChartDownloaderCallback(o)
}

type WithConcurrent int64

func (o WithConcurrent) applyToDependencyManager(dm *DependencyManager) {
	dm.concurrent = int64(o)
}

// NewDependencyManager returns a new DependencyManager configured with the given
// DependencyManagerOption list.
func NewDependencyManager(opts ...DependencyManagerOption) *DependencyManager {
	dm := &DependencyManager{}
	for _, v := range opts {
		v.applyToDependencyManager(dm)
	}
	return dm
}

// Clear iterates over the downloaders, calling Clear on all
// items. It returns an aggregate error of all Clear errors.
func (dm *DependencyManager) Clear() error {
	var errs []error
	for _, v := range dm.downloaders {
		if v != nil {
			errs = append(errs, v.Clear())
		}
	}
	return errors.NewAggregate(errs)
}

// Build compiles a set of missing dependencies from chart.Chart, and attempts to
// resolve and build them using the information from Reference.
// It returns the number of resolved local and remote dependencies, or an error.
func (dm *DependencyManager) Build(ctx context.Context, ref Reference, chart *helmchart.Chart) (int, error) {
	// Collect dependency metadata
	var (
		deps = chart.Dependencies()
		reqs = chart.Metadata.Dependencies
	)
	// Lock file takes precedence
	if lock := chart.Lock; lock != nil {
		reqs = lock.Dependencies
	}

	// Collect missing dependencies
	missing := collectMissing(deps, reqs)
	if len(missing) == 0 {
		return 0, nil
	}

	// Run the build for the missing dependencies
	if err := dm.build(ctx, ref, chart, missing); err != nil {
		return 0, err
	}
	return len(missing), nil
}

// chartWithLock holds a chart.Chart with a sync.Mutex to lock for writes.
type chartWithLock struct {
	*helmchart.Chart
	mu sync.Mutex
}

// build adds the given list of deps to the chart with the configured number of
// concurrent workers. If the chart.Chart references a local dependency but no
// LocalReference is given, or any dependency could not be added, an error
// is returned. The first error it encounters cancels all other workers.
func (dm *DependencyManager) build(ctx context.Context, ref Reference, c *helmchart.Chart, deps map[string]*helmchart.Dependency) error {
	current := dm.concurrent
	if current <= 0 {
		current = 1
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		sem := semaphore.NewWeighted(current)
		c := &chartWithLock{Chart: c}
		for name, dep := range deps {
			name, dep := name, dep
			if err := sem.Acquire(groupCtx, 1); err != nil {
				return err
			}
			group.Go(func() (err error) {
				defer sem.Release(1)
				if isLocalDep(dep) {
					localRef, ok := ref.(LocalReference)
					if !ok {
						err = fmt.Errorf("failed to add local dependency '%s': no local chart reference", name)
						return
					}
					if err = dm.addLocalDependency(localRef, c, dep); err != nil {
						err = fmt.Errorf("failed to add local dependency '%s': %w", name, err)
					}
					return
				}
				if err = dm.addRemoteDependency(c, dep); err != nil {
					err = fmt.Errorf("failed to add remote dependency '%s': %w", name, err)
				}
				return
			})
		}
		return nil
	})
	return group.Wait()
}

// addLocalDependency attempts to resolve and add the given local chart.Dependency
// to the chart.
func (dm *DependencyManager) addLocalDependency(ref LocalReference, c *chartWithLock, dep *helmchart.Dependency) error {
	sLocalChartPath, err := dm.secureLocalChartPath(ref, dep)
	if err != nil {
		return err
	}

	if _, err := os.Stat(sLocalChartPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no chart found at '%s' (reference '%s')", strings.TrimPrefix(sLocalChartPath, ref.WorkDir), dep.Repository)
		}
		return err
	}

	constraint, err := semver.NewConstraint(dep.Version)
	if err != nil {
		err = fmt.Errorf("invalid version/constraint format '%s': %w", dep.Version, err)
		return err
	}

	ch, err := secureloader.Load(ref.WorkDir, sLocalChartPath)
	if err != nil {
		return fmt.Errorf("failed to load chart from '%s' (reference '%s'): %w",
			strings.TrimPrefix(sLocalChartPath, ref.WorkDir), dep.Repository, err)
	}

	ver, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return err
	}

	if !constraint.Check(ver) {
		err = fmt.Errorf("can't get a valid version for constraint '%s'", dep.Version)
		return err
	}

	c.mu.Lock()
	c.AddDependency(ch)
	c.mu.Unlock()
	return nil
}

// addRemoteDependency attempts to resolve and add the given remote chart.Dependency
// to the chart. It locks the chartWithLock before the downloaded dependency is
// added to the chart.
func (dm *DependencyManager) addRemoteDependency(chart *chartWithLock, dep *helmchart.Dependency) error {
	repo, err := dm.resolveRepository(dep.Repository)
	if err != nil {
		return err
	}

	ver, err := repo.GetChartVersion(dep.Name, dep.Version)
	if err != nil {
		return fmt.Errorf("failed to get chart '%s' version '%s' from '%s': %w", dep.Name, dep.Version, dep.Repository, err)
	}
	res, err := repo.DownloadChart(ver)
	if err != nil {
		return fmt.Errorf("chart download of version '%s' failed: %w", ver.Version, err)
	}
	ch, err := secureloader.LoadArchive(res)
	if err != nil {
		return fmt.Errorf("failed to load downloaded archive of version '%s': %w", ver.Version, err)
	}

	chart.mu.Lock()
	chart.AddDependency(ch)
	chart.mu.Unlock()
	return nil
}

// resolveRepository first attempts to resolve the url from the downloaders, falling back
// to getDownloaderCallback if set. It returns the resolved Index, or an error.
func (dm *DependencyManager) resolveRepository(url string) (repo repository.Downloader, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	nUrl := repository.NormalizeURL(url)
	err = repository.ValidateDepURL(nUrl)
	if err != nil {
		return
	}
	if _, ok := dm.downloaders[nUrl]; !ok {
		if dm.getChartDownloaderCallback == nil {
			err = fmt.Errorf("no chart repository for URL '%s'", nUrl)
			return
		}

		if dm.downloaders == nil {
			dm.downloaders = map[string]repository.Downloader{}
		}

		if dm.downloaders[nUrl], err = dm.getChartDownloaderCallback(nUrl); err != nil {
			err = fmt.Errorf("failed to get chart repository for URL '%s': %w", nUrl, err)
			return
		}
	}
	return dm.downloaders[nUrl], nil
}

// secureLocalChartPath returns the secure absolute path of a local dependency.
// It does not allow the dependency's path to be outside the scope of
// LocalReference.WorkDir.
func (dm *DependencyManager) secureLocalChartPath(ref LocalReference, dep *helmchart.Dependency) (string, error) {
	localUrl, err := url.Parse(dep.Repository)
	if err != nil {
		return "", fmt.Errorf("failed to parse alleged local chart reference: %w", err)
	}
	if localUrl.Scheme != "" && localUrl.Scheme != "file" {
		return "", fmt.Errorf("'%s' is not a local chart reference", dep.Repository)
	}
	return securejoin.SecureJoin(ref.WorkDir, filepath.Join(ref.Path, localUrl.Host, localUrl.Path))
}

// collectMissing returns a map with dependencies from reqs that are missing
// from current, indexed by their alias or name. All dependencies of a chart
// are present if len of returned map == 0.
func collectMissing(current []*helmchart.Chart, reqs []*helmchart.Dependency) map[string]*helmchart.Dependency {
	// If the number of dependencies equals the number of requested
	// dependencies, there are no missing dependencies
	if len(current) == len(reqs) {
		return nil
	}

	// Build up a map of reqs that are not in current, indexed by their
	// alias or name
	var missing map[string]*helmchart.Dependency
	for _, dep := range reqs {
		name := dep.Name
		if dep.Alias != "" {
			name = dep.Alias
		}
		// Exclude existing dependencies
		found := false
		for _, existing := range current {
			if existing.Name() == name {
				found = true
			}
		}
		if found {
			continue
		}
		if missing == nil {
			missing = map[string]*helmchart.Dependency{}
		}
		missing[name] = dep
	}
	return missing
}

// isLocalDep returns true if the given chart.Dependency contains a local (file) path reference.
func isLocalDep(dep *helmchart.Dependency) bool {
	return dep.Repository == "" || strings.HasPrefix(dep.Repository, "file://")
}
