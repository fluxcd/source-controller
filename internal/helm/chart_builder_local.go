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
	"strings"

	"github.com/Masterminds/semver/v3"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/fluxcd/pkg/runtime/transform"
	"helm.sh/helm/v3/pkg/chart/loader"
	"sigs.k8s.io/yaml"
)

type localChartBuilder struct {
	dm *DependencyManager
}

// NewLocalChartBuilder returns a ChartBuilder capable of building a Helm
// chart with a LocalChartReference. For chart references pointing to a
// directory, the DependencyManager is used to resolve missing local and
// remote dependencies.
func NewLocalChartBuilder(dm *DependencyManager) ChartBuilder {
	return &localChartBuilder{
		dm: dm,
	}
}

func (b *localChartBuilder) Build(ctx context.Context, ref ChartReference, p string, opts BuildOptions) (*ChartBuild, error) {
	localRef, ok := ref.(LocalChartReference)
	if !ok {
		return nil, fmt.Errorf("expected local chart reference")
	}

	if err := ref.Validate(); err != nil {
		return nil, err
	}

	// Load the chart metadata from the LocalChartReference to ensure it points
	// to a chart
	curMeta, err := LoadChartMetadata(localRef.Path)
	if err != nil {
		return nil, err
	}

	result := &ChartBuild{}
	result.Name = curMeta.Name

	// Set build specific metadata if instructed
	result.Version = curMeta.Version
	if opts.VersionMetadata != "" {
		ver, err := semver.NewVersion(curMeta.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chart version from metadata as SemVer: %w", err)
		}
		if *ver, err = ver.SetMetadata(opts.VersionMetadata); err != nil {
			return nil, fmt.Errorf("failed to set metadata on chart version: %w", err)
		}
		result.Version = ver.String()
	}

	// If all the following is true, we do not need to package the chart:
	//	Chart version from metadata matches chart version for ref
	//	BuildOptions.Force is False
	if opts.CachedChart != "" && !opts.Force {
		if curMeta, err = LoadChartMetadataFromArchive(opts.CachedChart); err == nil && result.Version == curMeta.Version {
			result.Path = opts.CachedChart
			result.ValueFiles = opts.ValueFiles
			return result, nil
		}
	}

	// If the chart at the path is already packaged and no custom value files
	// options are set, we can copy the chart without making modifications
	isChartDir := pathIsDir(localRef.Path)
	if !isChartDir && len(opts.GetValueFiles()) == 0 {
		if err := copyFileToPath(localRef.Path, p); err != nil {
			return nil, err
		}
		result.Path = p
		return result, nil
	}

	// Merge chart values, if instructed
	var mergedValues map[string]interface{}
	if len(opts.GetValueFiles()) > 0 {
		if mergedValues, err = mergeFileValues(localRef.BaseDir, opts.ValueFiles); err != nil {
			return nil, fmt.Errorf("failed to merge value files: %w", err)
		}
	}

	// At this point we are certain we need to load the chart;
	// either to package it because it originates from a directory,
	// or because we have merged values and need to repackage
	chart, err := loader.Load(localRef.Path)
	if err != nil {
		return nil, err
	}
	// Set earlier resolved version (with metadata)
	chart.Metadata.Version = result.Version

	// Overwrite default values with merged values, if any
	if ok, err = OverwriteChartDefaultValues(chart, mergedValues); ok || err != nil {
		if err != nil {
			return nil, err
		}
		result.ValueFiles = opts.GetValueFiles()
	}

	// Ensure dependencies are fetched if building from a directory
	if isChartDir {
		if b.dm == nil {
			return nil, fmt.Errorf("local chart builder requires dependency manager for unpackaged charts")
		}
		if result.ResolvedDependencies, err = b.dm.Build(ctx, ref, chart); err != nil {
			return nil, err
		}
	}

	// Package the chart
	if err = packageToPath(chart, p); err != nil {
		return nil, err
	}
	result.Path = p
	result.Packaged = true
	return result, nil
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
