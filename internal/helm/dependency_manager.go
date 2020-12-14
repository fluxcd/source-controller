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
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sync/errgroup"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// DependencyWithRepository is a container for a dependency and its respective
// repository
type DependencyWithRepository struct {
	Dependency *helmchart.Dependency
	Repo       *ChartRepository
}

// DependencyManager manages dependencies for helm charts
type DependencyManager struct {
	BaseDir      string
	ChartPath    string
	Chart        *helmchart.Chart
	Dependencies []*DependencyWithRepository
}

// Build compiles and builds the chart dependencies
func (dm *DependencyManager) Build(ctx context.Context) error {
	if len(dm.Dependencies) == 0 {
		return nil
	}

	errs, ctx := errgroup.WithContext(ctx)
	for _, item := range dm.Dependencies {
		errs.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			var (
				ch  *helmchart.Chart
				err error
			)
			if strings.HasPrefix(item.Dependency.Repository, "file://") {
				ch, err = chartForLocalDependency(item.Dependency, dm.BaseDir, dm.ChartPath)
			} else {
				ch, err = chartForRemoteDependency(item.Dependency, item.Repo)
			}
			if err != nil {
				return err
			}
			dm.Chart.AddDependency(ch)
			return nil
		})
	}

	return errs.Wait()
}

func chartForLocalDependency(dep *helmchart.Dependency, baseDir, chartPath string) (*helmchart.Chart, error) {
	origPath, err := securejoin.SecureJoin(baseDir,
		filepath.Join(strings.TrimPrefix(chartPath, baseDir), strings.TrimPrefix(dep.Repository, "file://")))
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(origPath); os.IsNotExist(err) {
		err := fmt.Errorf("chart path %s not found: %w", origPath, err)
		return nil, err
	} else if err != nil {
		return nil, err
	}

	ch, err := loader.Load(origPath)
	if err != nil {
		return nil, err
	}

	constraint, err := semver.NewConstraint(dep.Version)
	if err != nil {
		err := fmt.Errorf("dependency %s has an invalid version/constraint format: %w", dep.Name, err)
		return nil, err
	}

	v, err := semver.NewVersion(ch.Metadata.Version)
	if err != nil {
		return nil, err
	}

	if !constraint.Check(v) {
		err = fmt.Errorf("can't get a valid version for dependency %s", dep.Name)
		return nil, err
	}

	return ch, nil
}

func chartForRemoteDependency(dep *helmchart.Dependency, chartRepo *ChartRepository) (*helmchart.Chart, error) {
	if chartRepo == nil {
		return nil, fmt.Errorf("chartrepo should not be nil")
	}

	// Lookup the chart version in the chart repository index
	chartVer, err := chartRepo.Get(dep.Name, dep.Version)
	if err != nil {
		return nil, err
	}

	// Download chart
	res, err := chartRepo.DownloadChart(chartVer)
	if err != nil {
		return nil, err
	}

	ch, err := loader.LoadArchive(res)
	if err != nil {
		return nil, err
	}

	return ch, nil
}
