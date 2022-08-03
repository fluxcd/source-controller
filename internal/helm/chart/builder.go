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

package chart

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"

	"github.com/fluxcd/source-controller/internal/fs"
)

// Reference holds information to locate a chart.
type Reference interface {
	// Validate returns an error if the Reference is not valid according
	// to the spec of the interface implementation.
	Validate() error
}

// LocalReference contains sufficient information to locate a chart on the
// local filesystem.
type LocalReference struct {
	// WorkDir used as chroot during build operations.
	// File references are not allowed to traverse outside it.
	WorkDir string
	// Path of the chart on the local filesystem relative to WorkDir.
	Path string
}

// Validate returns an error if the LocalReference does not have
// a Path set.
func (r LocalReference) Validate() error {
	if r.WorkDir == "" {
		return fmt.Errorf("no work dir set for local chart reference")
	}
	if r.Path == "" {
		return fmt.Errorf("no path set for local chart reference")
	}
	if !filepath.IsAbs(r.WorkDir) {
		return fmt.Errorf("local chart reference work dir is expected to be absolute")
	}
	if filepath.IsAbs(r.Path) {
		return fmt.Errorf("local chart reference path is expected to be relative")
	}
	return nil
}

// RemoteReference contains sufficient information to look up a chart in
// a ChartRepository.
type RemoteReference struct {
	// Name of the chart.
	Name string
	// Version of the chart.
	// Can be a Semver range, or empty for latest.
	Version string
}

// Validate returns an error if the RemoteReference does not have
// a Name set.
func (r RemoteReference) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("no name set for remote chart reference")
	}
	name := regexp.MustCompile("^([-a-z0-9]+/?)+$")
	if !name.MatchString(r.Name) {
		return fmt.Errorf("invalid chart name '%s': a valid name must be lower case letters and numbers and MAY be separated with dashes (-) or slashes (/)", r.Name)
	}
	return nil
}

// Builder is capable of building a (specific) chart Reference.
type Builder interface {
	// Build pulls and (optionally) packages a Helm chart with the given
	// Reference and BuildOptions, and writes it to p.
	// It returns the Build result, or an error.
	// It may return an error for unsupported Reference implementations.
	Build(ctx context.Context, ref Reference, p string, opts BuildOptions) (*Build, error)
}

// BuildOptions provides a list of options for Builder.Build.
type BuildOptions struct {
	// VersionMetadata can be set to SemVer build metadata as defined in
	// the spec, and is included during packaging.
	// Ref: https://semver.org/#spec-item-10
	VersionMetadata string
	// ValuesFiles can be set to a list of relative paths, used to compose
	// and overwrite an alternative default "values.yaml" for the chart.
	ValuesFiles []string
	// CachedChart can be set to the absolute path of a chart stored on
	// the local filesystem, and is used for simple validation by metadata
	// comparisons.
	CachedChart string
	// Force can be set to force the build of the chart, for example
	// because the list of ValuesFiles has changed.
	Force bool
}

// GetValuesFiles returns BuildOptions.ValuesFiles, except if it equals
// "values.yaml", which returns nil.
func (o BuildOptions) GetValuesFiles() []string {
	if len(o.ValuesFiles) == 1 && filepath.Clean(o.ValuesFiles[0]) == filepath.Clean(chartutil.ValuesfileName) {
		return nil
	}
	return o.ValuesFiles
}

// Build contains the (partial) Builder.Build result, including specific
// information about the built chart like ResolvedDependencies.
type Build struct {
	// Name of the chart.
	Name string
	// Version of the chart.
	Version string
	// Path is the absolute path to the packaged chart.
	// Can be empty, in which case a failure should be assumed.
	Path string
	// ValuesFiles is the list of files used to compose the chart's
	// default "values.yaml".
	ValuesFiles []string
	// ResolvedDependencies is the number of local and remote dependencies
	// collected by the DependencyManager before building the chart.
	ResolvedDependencies int
	// Packaged indicates if the Builder has packaged the chart.
	// This can for example be false if ValuesFiles is empty and the chart
	// source was already packaged.
	Packaged bool
}

// Summary returns a human-readable summary of the Build.
func (b *Build) Summary() string {
	if !b.HasMetadata() {
		return "no chart build"
	}

	var s strings.Builder

	var action = "new"
	if b.Path != "" {
		action = "pulled"
		if b.Packaged {
			action = "packaged"
		}
	}
	s.WriteString(fmt.Sprintf("%s '%s' chart with version '%s'", action, b.Name, b.Version))

	if len(b.ValuesFiles) > 0 {
		s.WriteString(fmt.Sprintf(" and merged values files %v", b.ValuesFiles))
	}

	return s.String()
}

// HasMetadata returns if the Build contains chart metadata.
//
// NOTE: This may return True while the build did not Complete successfully.
// Which means it was able to successfully collect the metadata from the chart,
// but failed further into the process.
func (b *Build) HasMetadata() bool {
	if b == nil {
		return false
	}
	return b.Name != "" && b.Version != ""
}

// Complete returns if the Build completed successfully.
func (b *Build) Complete() bool {
	return b.HasMetadata() && b.Path != ""
}

// String returns the Path of the Build.
func (b *Build) String() string {
	if b == nil {
		return ""
	}
	return b.Path
}

// packageToPath attempts to package the given chart to the out filepath.
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
