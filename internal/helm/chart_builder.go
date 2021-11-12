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

	"github.com/fluxcd/source-controller/internal/fs"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

// ChartReference holds information to locate a chart.
type ChartReference interface {
	// Validate returns an error if the ChartReference is not valid according
	// to the spec of the interface implementation.
	Validate() error
}

// LocalChartReference contains sufficient information to locate a chart on the
// local filesystem.
type LocalChartReference struct {
	// BaseDir used as chroot during build operations.
	// File references are not allowed to traverse outside it.
	BaseDir string
	// Path of the chart on the local filesystem.
	Path string
}

// Validate returns an error if the LocalChartReference does not have
// a Path set.
func (r LocalChartReference) Validate() error {
	if r.Path == "" {
		return fmt.Errorf("no path set for local chart reference")
	}
	return nil
}

// RemoteChartReference contains sufficient information to look up a chart in
// a ChartRepository.
type RemoteChartReference struct {
	// Name of the chart.
	Name string
	// Version of the chart.
	// Can be a Semver range, or empty for latest.
	Version string
}

// Validate returns an error if the RemoteChartReference does not have
// a Name set.
func (r RemoteChartReference) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("no name set for remote chart reference")
	}
	return nil
}

// ChartBuilder is capable of building a (specific) ChartReference.
type ChartBuilder interface {
	// Build builds and packages a Helm chart with the given ChartReference
	// and BuildOptions and writes it to p. It returns the ChartBuild result,
	// or an error. It may return an error for unsupported ChartReference
	// implementations.
	Build(ctx context.Context, ref ChartReference, p string, opts BuildOptions) (*ChartBuild, error)
}

// BuildOptions provides a list of options for ChartBuilder.Build.
type BuildOptions struct {
	// VersionMetadata can be set to SemVer build metadata as defined in
	// the spec, and is included during packaging.
	// Ref: https://semver.org/#spec-item-10
	VersionMetadata string
	// ValueFiles can be set to a list of relative paths, used to compose
	// and overwrite an alternative default "values.yaml" for the chart.
	ValueFiles []string
	// CachedChart can be set to the absolute path of a chart stored on
	// the local filesystem, and is used for simple validation by metadata
	// comparisons.
	CachedChart string
	// Force can be set to force the build of the chart, for example
	// because the list of ValueFiles has changed.
	Force bool
}

// GetValueFiles returns BuildOptions.ValueFiles, except if it equals
// "values.yaml", which returns nil.
func (o BuildOptions) GetValueFiles() []string {
	if len(o.ValueFiles) == 1 && filepath.Clean(o.ValueFiles[0]) == filepath.Clean(chartutil.ValuesfileName) {
		return nil
	}
	return o.ValueFiles
}

// ChartBuild contains the ChartBuilder.Build result, including specific
// information about the built chart like ResolvedDependencies.
type ChartBuild struct {
	// Path is the absolute path to the packaged chart.
	Path string
	// Name of the packaged chart.
	Name string
	// Version of the packaged chart.
	Version string
	// ValueFiles is the list of files used to compose the chart's
	// default "values.yaml".
	ValueFiles []string
	// ResolvedDependencies is the number of local and remote dependencies
	// collected by the DependencyManager before building the chart.
	ResolvedDependencies int
	// Packaged indicates if the ChartBuilder has packaged the chart.
	// This can for example be false if ValueFiles is empty and the chart
	// source was already packaged.
	Packaged bool
}

// Summary returns a human-readable summary of the ChartBuild.
func (b *ChartBuild) Summary() string {
	if b == nil {
		return "no chart build"
	}

	var s strings.Builder

	action := "Fetched"
	if b.Packaged {
		action = "Packaged"
	}
	s.WriteString(fmt.Sprintf("%s '%s' chart with version '%s'.", action, b.Name, b.Version))

	if b.Packaged && b.ResolvedDependencies > 0 {
		s.WriteString(fmt.Sprintf(" Resolved %d dependencies before packaging.", b.ResolvedDependencies))
	}

	if len(b.ValueFiles) > 0 {
		s.WriteString(fmt.Sprintf(" Merged %v value files into default chart values.", b.ValueFiles))
	}

	return s.String()
}

// String returns the Path of the ChartBuild.
func (b *ChartBuild) String() string {
	if b != nil {
		return b.Path
	}
	return ""
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
	if err = fs.RenameWithFallback(p, out); err != nil {
		return fmt.Errorf("failed to write chart to file: %w", err)
	}
	return nil
}
