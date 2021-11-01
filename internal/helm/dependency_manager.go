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

// DependencyWithRepository is a container for a Helm chart dependency
// and its respective repository.
type DependencyWithRepository struct {
	// Dependency holds the reference to a chart.Chart dependency.
	Dependency *helmchart.Dependency
	// Repository is the ChartRepository the dependency should be
	// available at and can be downloaded from. If there is none,
	// a local ('file://') dependency is assumed.
	Repository *ChartRepository
}

// DependencyManager manages dependencies for a Helm chart.
type DependencyManager struct {
	// WorkingDir is the chroot path for dependency manager operations,
	// Dependencies that hold a local (relative) path reference are not
	// allowed to traverse outside this directory.
	WorkingDir string
	// ChartPath is the path of the Chart relative to the WorkingDir,
	// the combination of the WorkingDir and ChartPath is used to
	// determine the absolute path of a local dependency.
	ChartPath string
	// Chart holds the loaded chart.Chart from the ChartPath.
	Chart *helmchart.Chart
	// Dependencies contains a list of dependencies, and the respective
	// repository the dependency can be found at.
	Dependencies []*DependencyWithRepository
	// Workers is the number of concurrent chart-add operations during
	// Build. Defaults to 1 (non-concurrent).
	Workers int64

	mu sync.Mutex
}

// Build compiles and builds the dependencies of the Chart with the
// configured number of Workers.
func (dm *DependencyManager) Build(ctx context.Context) error {
	if len(dm.Dependencies) == 0 {
		return nil
	}

	workers := dm.Workers
	if workers <= 0 {
		workers = 1
	}

	defer func() {
		for _, dep := range dm.Dependencies {
			dep.Repository.UnloadIndex()
		}
	}()

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		sem := semaphore.NewWeighted(workers)
		for _, dep := range dm.Dependencies {
			dep := dep
			if err := sem.Acquire(groupCtx, 1); err != nil {
				return err
			}
			group.Go(func() error {
				defer sem.Release(1)
				if dep.Repository == nil {
					return dm.addLocalDependency(dep)
				}
				return dm.addRemoteDependency(dep)
			})
		}
		return nil
	})

	return group.Wait()
}

func (dm *DependencyManager) addLocalDependency(dpr *DependencyWithRepository) error {
	sLocalChartPath, err := dm.secureLocalChartPath(dpr)
	if err != nil {
		return err
	}

	if _, err := os.Stat(sLocalChartPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no chart found at '%s' (reference '%s') for dependency '%s'",
				strings.TrimPrefix(sLocalChartPath, dm.WorkingDir), dpr.Dependency.Repository, dpr.Dependency.Name)
		}
		return err
	}

	ch, err := loader.Load(sLocalChartPath)
	if err != nil {
		return err
	}

	constraint, err := semver.NewConstraint(dpr.Dependency.Version)
	if err != nil {
		err := fmt.Errorf("dependency '%s' has an invalid version/constraint format: %w", dpr.Dependency.Name, err)
		return err
	}

	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return err
	}

	if !constraint.Check(v) {
		err = fmt.Errorf("can't get a valid version for dependency '%s'", dpr.Dependency.Name)
		return err
	}

	dm.mu.Lock()
	dm.Chart.AddDependency(ch)
	dm.mu.Unlock()

	return nil
}

func (dm *DependencyManager) addRemoteDependency(dpr *DependencyWithRepository) error {
	if dpr.Repository == nil {
		return fmt.Errorf("no HelmRepository for '%s' dependency", dpr.Dependency.Name)
	}

	if !dpr.Repository.HasIndex() {
		if !dpr.Repository.HasCacheFile() {
			if _, err := dpr.Repository.CacheIndex(); err != nil {
				return err
			}
		}
		if err := dpr.Repository.LoadFromCache(); err != nil {
			return err
		}
	}

	chartVer, err := dpr.Repository.Get(dpr.Dependency.Name, dpr.Dependency.Version)
	if err != nil {
		return err
	}

	res, err := dpr.Repository.DownloadChart(chartVer)
	if err != nil {
		return err
	}

	ch, err := loader.LoadArchive(res)
	if err != nil {
		return err
	}

	dm.mu.Lock()
	dm.Chart.AddDependency(ch)
	dm.mu.Unlock()
	return nil
}

func (dm *DependencyManager) secureLocalChartPath(dep *DependencyWithRepository) (string, error) {
	localUrl, err := url.Parse(dep.Dependency.Repository)
	if err != nil {
		return "", fmt.Errorf("failed to parse alleged local chart reference: %w", err)
	}
	if localUrl.Scheme != "" && localUrl.Scheme != "file" {
		return "", fmt.Errorf("'%s' is not a local chart reference", dep.Dependency.Repository)
	}
	return securejoin.SecureJoin(dm.WorkingDir, filepath.Join(dm.ChartPath, localUrl.Host, localUrl.Path))
}
