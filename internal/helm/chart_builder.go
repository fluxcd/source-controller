/*
Copyright 2021 The Flux authors

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
	"sync"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/source-controller/internal/fs"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/runtime/transform"
)

// ChartBuilder aims to efficiently build a Helm chart from a directory or packaged chart.
// It avoids or delays loading the chart into memory in full, working with chart.Metadata
// as much as it can, and returns early (by copying over the already packaged source chart)
// if no modifications were made during the build process.
type ChartBuilder struct {
	// baseDir is the chroot for the chart builder when path isDir.
	// It must be (a higher) relative to path. File references (during e.g.
	// value file merge operations) are not allowed to traverse out of it.
	baseDir string

	// path is the file or directory path to a chart source.
	path string

	// chart holds a (partly) loaded chart.Chart, it contains at least the
	// chart.Metadata, which may expand to the full chart.Chart if required
	// for Build operations.
	chart *helmchart.Chart

	// valueFiles holds a list of path references of valueFiles that should be
	// merged and packaged as a single "values.yaml" during Build.
	valueFiles []string

	// repositories holds an index of repository URLs and their ChartRepository.
	// They are used to configure a DependencyManager for missing chart dependencies
	// if isDir is true.
	repositories map[string]*ChartRepository

	// getChartRepositoryCallback is used to configure a DependencyManager for
	// missing chart dependencies if isDir is true.
	getChartRepositoryCallback GetChartRepositoryCallback

	mu sync.Mutex
}

// NewChartBuilder constructs a new ChartBuilder for the given chart path.
// It returns an error if no chart.Metadata can be loaded from the path.
func NewChartBuilder(path string) (*ChartBuilder, error) {
	metadata, err := LoadChartMetadata(path)
	if err != nil {
		return nil, fmt.Errorf("could not create new chart builder: %w", err)
	}
	return &ChartBuilder{
		path:  path,
		chart: &helmchart.Chart{
			Metadata: metadata,
		},
	}, nil
}

// WithBaseDir configures the base dir on the ChartBuilder.
func (b *ChartBuilder) WithBaseDir(p string) *ChartBuilder {
	b.mu.Lock()
	b.baseDir = p
	b.mu.Unlock()
	return b
}

// WithValueFiles appends the given paths to the ChartBuilder's valueFiles.
func (b *ChartBuilder) WithValueFiles(path ...string) *ChartBuilder {
	b.mu.Lock()
	b.valueFiles = append(b.valueFiles, path...)
	b.mu.Unlock()
	return b
}

// WithChartRepository indexes the given ChartRepository by the NormalizeChartRepositoryURL,
// used to configure the DependencyManager if the chart is not packaged.
func (b *ChartBuilder) WithChartRepository(url string, index *ChartRepository) *ChartBuilder {
	b.mu.Lock()
	b.repositories[NormalizeChartRepositoryURL(url)] = index
	b.mu.Unlock()
	return b
}

// WithChartRepositoryCallback configures the GetChartRepositoryCallback used by the
// DependencyManager if the chart is not packaged.
func (b *ChartBuilder) WithChartRepositoryCallback(c GetChartRepositoryCallback) *ChartBuilder {
	b.mu.Lock()
	b.getChartRepositoryCallback = c
	b.mu.Unlock()
	return b
}

// ChartBuildResult contains the ChartBuilder result, including build specific
// information about the chart.
type ChartBuildResult struct {
	// SourceIsDir indicates if the chart was build from a directory.
	SourceIsDir bool
	// Path contains the absolute path to the packaged chart.
	Path string
	// ValuesOverwrite holds a structured map with the merged values used
	// to overwrite chart default "values.yaml".
	ValuesOverwrite map[string]interface{}
	// CollectedDependencies contains the number of missing local and remote
	// dependencies that were collected by the DependencyManager before building
	// the chart.
	CollectedDependencies int
	// Packaged indicates if the ChartBuilder has packaged the chart.
	// This can for example be false if SourceIsDir is false and ValuesOverwrite
	// is nil, which makes the ChartBuilder copy the chart source to Path without
	// making any modifications.
	Packaged bool
}

// String returns the Path of the ChartBuildResult.
func (b *ChartBuildResult) String() string {
	if b != nil {
		return b.Path
	}
	return ""
}

// Build attempts to build a new chart using ChartBuilder configuration,
// writing it to the provided path.
// It returns a ChartBuildResult containing all information about the resulting chart,
// or an error.
func (b *ChartBuilder) Build(ctx context.Context, p string) (_ *ChartBuildResult, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.chart == nil {
		err = fmt.Errorf("chart build failed: no initial chart (metadata) loaded")
		return
	}
	if b.path == "" {
		err = fmt.Errorf("chart build failed: no path set")
		return
	}

	result := &ChartBuildResult{}
	result.SourceIsDir = pathIsDir(b.path)
	result.Path = p

	// Merge chart values
	if err = b.mergeValues(result); err != nil {
		err = fmt.Errorf("chart build failed: %w", err)
		return
	}

	// Ensure chart has all dependencies
	if err = b.buildDependencies(ctx, result); err != nil {
		err = fmt.Errorf("chart build failed: %w", err)
		return
	}

	// Package (or copy) chart
	if err = b.packageChart(result); err != nil {
		err = fmt.Errorf("chart package failed: %w", err)
		return
	}
	return result, nil
}

// load lazy-loads chart.Chart into chart from the set path, it replaces any previously set
// chart.Metadata shim.
func (b *ChartBuilder) load() (err error) {
	if b.chart == nil || len(b.chart.Files) <= 0 {
		if b.path == "" {
			return fmt.Errorf("failed to load chart: path not set")
		}
		chart, err := loader.Load(b.path)
		if err != nil {
			return fmt.Errorf("failed to load chart: %w", err)
		}
		b.chart = chart
	}
	return
}

// buildDependencies builds the missing dependencies for a chart from a directory.
// Using the chart using a NewDependencyManager and the configured repositories
// and getChartRepositoryCallback
// It returns the number of dependencies it collected, or an error.
func (b *ChartBuilder) buildDependencies(ctx context.Context, result *ChartBuildResult) (err error) {
	if !result.SourceIsDir {
		return
	}

	if err = b.load(); err != nil {
		err = fmt.Errorf("failed to ensure chart has no missing dependencies: %w", err)
		return
	}

	 dm := NewDependencyManager(b.chart, b.baseDir, strings.TrimLeft(b.path, b.baseDir)).
		WithRepositories(b.repositories).
		WithChartRepositoryCallback(b.getChartRepositoryCallback)

	result.CollectedDependencies, err = dm.Build(ctx)
	return
}

// mergeValues strategically merges the valueFiles, it merges using mergeFileValues
// or mergeChartValues depending on if the chart is sourced from a package or directory.
// Ir only calls load to propagate the chart if required by the strategy.
// It returns the merged values, or an error.
func (b *ChartBuilder) mergeValues(result *ChartBuildResult) (err error) {
	if len(b.valueFiles) == 0 {
		return
	}

	if result.SourceIsDir {
		result.ValuesOverwrite, err = mergeFileValues(b.baseDir, b.valueFiles)
		if err != nil {
			err = fmt.Errorf("failed to merge value files: %w", err)
		}
		return
	}

	// Values equal to default
	if len(b.valueFiles) == 1 && b.valueFiles[0] == chartutil.ValuesfileName {
		return
	}

	if err = b.load(); err != nil {
		err = fmt.Errorf("failed to merge chart values: %w", err)
		return
	}

	if result.ValuesOverwrite, err = mergeChartValues(b.chart, b.valueFiles); err != nil {
		err = fmt.Errorf("failed to merge chart values: %w", err)
		return
	}
	return nil
}

// packageChart determines if it should copyFileToPath or packageToPath
// based on the provided result. It sets Packaged on ChartBuildResult to
// true if packageToPath is successful.
func (b *ChartBuilder) packageChart(result *ChartBuildResult) error {
	// If we are not building from a directory, and we do not have any
	// replacement values, we can copy over the already packaged source
	// chart without making any modifications
	if !result.SourceIsDir && len(result.ValuesOverwrite) == 0 {
		if err := copyFileToPath(b.path, result.Path); err != nil {
			return fmt.Errorf("chart build failed: %w", err)
		}
		return nil
	}

	// Package chart to a new temporary directory
	if err := packageToPath(b.chart, result.Path); err != nil {
		return fmt.Errorf("chart build failed: %w", err)
	}
	result.Packaged = true
	return nil
}

// mergeChartValues merges the given chart.Chart Files paths into a single "values.yaml" map.
// It returns the merge result, or an error.
func mergeChartValues(chart *helmchart.Chart, paths []string) (map[string]interface{}, error) {
	mergedValues := make(map[string]interface{})
	for _, p := range paths {
		cfn := filepath.Clean(p)
		if cfn == chartutil.ValuesfileName {
			mergedValues = transform.MergeMaps(mergedValues, chart.Values)
			continue
		}
		var b []byte
		for _, f := range chart.Files {
			if f.Name == cfn {
				b = f.Data
				break
			}
		}
		if b == nil {
			return nil, fmt.Errorf("no values file found at path '%s'", p)
		}
		values := make(map[string]interface{})
		if err := yaml.Unmarshal(b, &values); err != nil {
			return nil, fmt.Errorf("unmarshaling values from '%s' failed: %w", p, err)
		}
		mergedValues = transform.MergeMaps(mergedValues, values)
	}
	return mergedValues, nil
}

// mergeFileValues merges the given value file paths into a single "values.yaml" map.
// The provided (relative) paths may not traverse outside baseDir. It returns the merge
// result, or an error.
func mergeFileValues(baseDir string, paths []string) (map[string]interface{}, error) {
	mergedValues := make(map[string]interface{})
	for _, p := range paths {
		secureP, err := securejoin.SecureJoin(baseDir, p)
		if err != nil {
			return nil, err
		}
		if f, err := os.Stat(secureP); os.IsNotExist(err) || !f.Mode().IsRegular() {
			return nil, fmt.Errorf("no values file found at path '%s' (reference '%s')",
				strings.TrimPrefix(secureP, baseDir), p)
		}
		b, err := os.ReadFile(secureP)
		if err != nil {
			return nil, fmt.Errorf("could not read values from file '%s': %w", p, err)
		}
		values := make(map[string]interface{})
		err = yaml.Unmarshal(b, &values)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling values from '%s' failed: %w", p, err)
		}
		mergedValues = transform.MergeMaps(mergedValues, values)
	}
	return mergedValues, nil
}

// copyFileToPath attempts to copy in to out. It returns an error if out already exists.
func copyFileToPath(in, out string) error {
	o, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("failed to create copy target: %w", err)
	}
	defer o.Close()
	i, err := os.Open(in)
	if err != nil {
		return fmt.Errorf("failed to open file to copy from: %w", err)
	}
	defer i.Close()
	if _, err := o.ReadFrom(i); err != nil {
		return fmt.Errorf("failed to read from source during copy: %w", err)
	}
	return nil
}

// packageToPath attempts to package the given chart.Chart to the out filepath.
func packageToPath(chart *helmchart.Chart, out string) error {
	o, err := os.MkdirTemp("", "chart-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory for chart: %w", err)
	}
	defer os.RemoveAll(o)

	p, err := chartutil.Save(chart, o)
	if err != nil {
		return fmt.Errorf("failed to package chart: %w", err)
	}
	return fs.RenameWithFallback(p, out)
}

// pathIsDir returns a boolean indicating if the given path points to a directory.
// In case os.Stat on the given path returns an error it returns false as well.
func pathIsDir(p string) bool {
	if p == "" {
		return false
	}
	if i, err := os.Stat(p); err != nil || !i.IsDir() {
		return false
	}
	return true
}
