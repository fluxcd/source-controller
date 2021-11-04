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
	"helm.sh/helm/v3/pkg/chart/loader"
)

// GetChartRepositoryCallback must return a ChartRepository for the URL,
// or an error describing why it could not be returned.
type GetChartRepositoryCallback func(url string) (*ChartRepository, error)

// DependencyManager manages dependencies for a Helm chart, downloading
// only those that are missing from the chart it holds.
type DependencyManager struct {
	// chart contains the chart.Chart from the path.
	chart *helmchart.Chart

	// baseDir is the chroot path for dependency manager operations,
	// Dependencies that hold a local (relative) path reference are not
	// allowed to traverse outside this directory.
	baseDir string

	// path is the path of the chart relative to the baseDir,
	// the combination of the baseDir and path is used to
	// determine the absolute path of a local dependency.
	path string

	// repositories contains a map of ChartRepository indexed by their
	// normalized URL. It is used as a lookup table for missing
	// dependencies.
	repositories map[string]*ChartRepository

	// getChartRepositoryCallback can be set to an on-demand get
	// callback which returned result is cached to repositories.
	getChartRepositoryCallback GetChartRepositoryCallback

	// workers is the number of concurrent chart-add operations during
	// Build. Defaults to 1 (non-concurrent).
	workers int64

	// mu contains the lock for chart writes.
	mu sync.Mutex
}

func NewDependencyManager(chart *helmchart.Chart, baseDir, path string) *DependencyManager {
	return &DependencyManager{
		chart:   chart,
		baseDir: baseDir,
		path:    path,
	}
}

func (dm *DependencyManager) WithRepositories(r map[string]*ChartRepository) *DependencyManager {
	dm.repositories = r
	return dm
}

func (dm *DependencyManager) WithChartRepositoryCallback(c GetChartRepositoryCallback) *DependencyManager {
	dm.getChartRepositoryCallback = c
	return dm
}

func (dm *DependencyManager) WithWorkers(w int64) *DependencyManager {
	dm.workers = w
	return dm
}

// Build compiles and builds the dependencies of the chart with the
// configured number of workers.
func (dm *DependencyManager) Build(ctx context.Context) (int, error) {
	// Collect dependency metadata
	var (
		deps = dm.chart.Dependencies()
		reqs = dm.chart.Metadata.Dependencies
	)
	// Lock file takes precedence
	if lock := dm.chart.Lock; lock != nil {
		reqs = lock.Dependencies
	}

	// Collect missing dependencies
	missing := collectMissing(deps, reqs)
	if len(missing) == 0 {
		return 0, nil
	}

	// Run the build for the missing dependencies
	if err := dm.build(ctx, missing); err != nil {
		return 0, err
	}
	return len(missing), nil
}

// build (concurrently) adds the given list of deps to the chart with the configured
// number of workers. It returns the first error, cancelling all other workers.
func (dm *DependencyManager) build(ctx context.Context, deps map[string]*helmchart.Dependency) error {
	workers := dm.workers
	if workers <= 0 {
		workers = 1
	}

	// Garbage collect temporary cached ChartRepository indexes
	defer func() {
		for _, v := range dm.repositories {
			v.Unload()
			_ = v.RemoveCache()
		}
	}()

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		sem := semaphore.NewWeighted(workers)
		for name, dep := range deps {
			name, dep := name, dep
			if err := sem.Acquire(groupCtx, 1); err != nil {
				return err
			}
			group.Go(func() (err error) {
				defer sem.Release(1)
				if isLocalDep(dep) {
					if err = dm.addLocalDependency(dep); err != nil {
						err = fmt.Errorf("failed to add local dependency '%s': %w", name, err)
					}
					return
				}
				if err = dm.addRemoteDependency(dep); err != nil {
					err = fmt.Errorf("failed to add remote dependency '%s': %w", name, err)
				}
				return
			})
		}
		return nil
	})
	return group.Wait()
}

// addLocalDependency attempts to resolve and add the given local chart.Dependency to the chart.
func (dm *DependencyManager) addLocalDependency(dep *helmchart.Dependency) error {
	sLocalChartPath, err := dm.secureLocalChartPath(dep)
	if err != nil {
		return err
	}

	if _, err := os.Stat(sLocalChartPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no chart found at '%s' (reference '%s')",
				strings.TrimPrefix(sLocalChartPath, dm.baseDir), dep.Repository)
		}
		return err
	}

	constraint, err := semver.NewConstraint(dep.Version)
	if err != nil {
		err = fmt.Errorf("invalid version/constraint format '%s': %w", dep.Version, err)
		return err
	}

	ch, err := loader.Load(sLocalChartPath)
	if err != nil {
		return fmt.Errorf("failed to load chart from '%s' (reference '%s'): %w",
			strings.TrimPrefix(sLocalChartPath, dm.baseDir), dep.Repository, err)
	}

	ver, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return err
	}

	if !constraint.Check(ver) {
		err = fmt.Errorf("can't get a valid version for constraint '%s'", dep.Version)
		return err
	}

	dm.mu.Lock()
	dm.chart.AddDependency(ch)
	dm.mu.Unlock()
	return nil
}

// addRemoteDependency attempts to resolve and add the given remote chart.Dependency to the chart.
func (dm *DependencyManager) addRemoteDependency(dep *helmchart.Dependency) error {
	repo, err := dm.resolveRepository(dep.Repository)
	if err != nil {
		return err
	}

	if err = repo.StrategicallyLoadIndex(); err != nil {
		return fmt.Errorf("failed to load index for '%s': %w", dep.Name, err)
	}


	ver, err := repo.Get(dep.Name, dep.Version)
	if err != nil {
		return err
	}
	res, err := repo.DownloadChart(ver)
	if err != nil {
		return fmt.Errorf("chart download of version '%s' failed: %w", ver.Version, err)
	}
	ch, err := loader.LoadArchive(res)
	if err != nil {
		return fmt.Errorf("failed to load downloaded archive of version '%s': %w", ver.Version, err)
	}

	dm.mu.Lock()
	dm.chart.AddDependency(ch)
	dm.mu.Unlock()
	return nil
}

// resolveRepository first attempts to resolve the url from the repositories, falling back
// to getChartRepositoryCallback if set. It returns the resolved ChartRepository, or an error.
func (dm *DependencyManager) resolveRepository(url string) (_ *ChartRepository, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	nUrl := NormalizeChartRepositoryURL(url)
	if _, ok := dm.repositories[nUrl]; !ok {
		if dm.getChartRepositoryCallback == nil {
			err = fmt.Errorf("no chart repository for URL '%s'", nUrl)
			return
		}
		if dm.repositories == nil {
			dm.repositories = map[string]*ChartRepository{}
		}
		if dm.repositories[nUrl], err = dm.getChartRepositoryCallback(nUrl); err != nil {
			err = fmt.Errorf("failed to get chart repository for URL '%s': %w", nUrl, err)
			return
		}
	}
	return dm.repositories[nUrl], nil
}

// secureLocalChartPath returns the secure absolute path of a local dependency.
// It does not allow the dependency's path to be outside the scope of baseDir.
func (dm *DependencyManager) secureLocalChartPath(dep *helmchart.Dependency) (string, error) {
	localUrl, err := url.Parse(dep.Repository)
	if err != nil {
		return "", fmt.Errorf("failed to parse alleged local chart reference: %w", err)
	}
	if localUrl.Scheme != "" && localUrl.Scheme != "file" {
		return "", fmt.Errorf("'%s' is not a local chart reference", dep.Repository)
	}
	return securejoin.SecureJoin(dm.baseDir, filepath.Join(dm.path, localUrl.Host, localUrl.Path))
}

// collectMissing returns a map with reqs that are missing from current,
// indexed by their alias or name. All dependencies of a chart are present
// if len of returned value == 0.
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
