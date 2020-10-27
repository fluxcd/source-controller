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

package controllers

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/fluxcd/source-controller/internal/helm"
	"golang.org/x/sync/errgroup"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

// DependencyWithRepository is a container for a dependency and its respective
// repository
type DependencyWithRepository struct {
	Dependency *helmchart.Dependency
	Repo       *helm.ChartRepository
}

// DependencyManager manages dependencies for helm charts
type DependencyManager struct {
	Chart        *helmchart.Chart
	ChartPath    string
	Dependencies []*DependencyWithRepository
}

// Build compiles and builds the chart dependencies
func (dm *DependencyManager) Build() error {
	if dm.Dependencies == nil {
		return nil
	}

	ctx := context.Background()
	errs, ctx := errgroup.WithContext(ctx)

	for _, item := range dm.Dependencies {
		dep := item.Dependency
		chartRepo := item.Repo
		errs.Go(func() error {
			var (
				ch  *helmchart.Chart
				err error
			)
			if strings.HasPrefix(dep.Repository, "file://") {
				ch, err = chartForLocalDependency(dep, dm.ChartPath)
			} else {
				ch, err = chartForRemoteDependency(dep, chartRepo)
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

func chartForLocalDependency(dep *helmchart.Dependency, cp string) (*helmchart.Chart, error) {
	origPath, err := filepath.Abs(path.Join(cp, strings.TrimPrefix(dep.Repository, "file://")))
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

func chartForRemoteDependency(dep *helmchart.Dependency, chartrepo *helm.ChartRepository) (*helmchart.Chart, error) {
	if chartrepo == nil {
		err := fmt.Errorf("chartrepo should not be nil")
		return nil, err
	}

	// Lookup the chart version in the chart repository index
	chartVer, err := chartrepo.Get(dep.Name, dep.Version)
	if err != nil {
		return nil, err
	}

	// Download chart
	res, err := chartrepo.DownloadChart(chartVer)
	if err != nil {
		return nil, err
	}

	ch, err := loader.LoadArchive(res)
	if err != nil {
		return nil, err
	}

	return ch, nil
}
