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
	"helm.sh/helm/v3/pkg/chart/loader"

	"github.com/fluxcd/source-controller/internal/helm/repository"
)

// GetChartRepositoryCallback must return a repository.ChartRepository for the
// URL, or an error describing why it could not be returned.
type GetChartRepositoryCallback func(url string) (*repository.ChartRepository, error)

// DependencyManager manages dependencies for a Helm chart.
type DependencyManager struct {
	// repositories contains a map of Index indexed by their
	// normalized URL. It is used as a lookup table for missing
	// dependencies.
	repositories map[string]*repository.ChartRepository

	// getRepositoryCallback can be set to an on-demand GetChartRepositoryCallback
	// which returned result is cached to repositories.
	getRepositoryCallback GetChartRepositoryCallback

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

type WithRepositories map[string]*repository.ChartRepository

func (o WithRepositories) applyToDependencyManager(dm *DependencyManager) {
	dm.repositories = o
}

type WithRepositoryCallback GetChartRepositoryCallback

func (o WithRepositoryCallback) applyToDependencyManager(dm *DependencyManager) {
	dm.getRepositoryCallback = GetChartRepositoryCallback(o)
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

func (dm *DependencyManager) Clear() []error {
	var errs []error
	for _, v := range dm.repositories {
		v.Unload()
		if err := v.RemoveCache(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
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
			return fmt.Errorf("no chart found at '%s' (reference '%s')", sLocalChartPath, dep.Repository)
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

	chart.mu.Lock()
	chart.AddDependency(ch)
	chart.mu.Unlock()
	return nil
}

// resolveRepository first attempts to resolve the url from the repositories, falling back
// to getRepositoryCallback if set. It returns the resolved Index, or an error.
func (dm *DependencyManager) resolveRepository(url string) (_ *repository.ChartRepository, err error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	nUrl := repository.NormalizeURL(url)
	if _, ok := dm.repositories[nUrl]; !ok {
		if dm.getRepositoryCallback == nil {
			err = fmt.Errorf("no chart repository for URL '%s'", nUrl)
			return
		}
		if dm.repositories == nil {
			dm.repositories = map[string]*repository.ChartRepository{}
		}
		if dm.repositories[nUrl], err = dm.getRepositoryCallback(nUrl); err != nil {
			err = fmt.Errorf("failed to get chart repository for URL '%s': %w", nUrl, err)
			return
		}
	}
	return dm.repositories[nUrl], nil
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
	relPath, err := filepath.Rel(ref.WorkDir, ref.Path)
	if err != nil {
		relPath = ref.Path
	}
	return securejoin.SecureJoin(ref.WorkDir, filepath.Join(relPath, localUrl.Host, localUrl.Path))
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
