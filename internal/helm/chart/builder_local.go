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
	"strings"

	"github.com/Masterminds/semver/v3"
	securejoin "github.com/cyphar/filepath-securejoin"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/runtime/transform"

	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader"
)

type localChartBuilder struct {
	dm *DependencyManager
}

// NewLocalBuilder returns a Builder capable of building a Helm chart with a
// LocalReference. For chart references pointing to a directory, the
// DependencyManager is used to resolve missing local and remote dependencies.
func NewLocalBuilder(dm *DependencyManager) Builder {
	return &localChartBuilder{
		dm: dm,
	}
}

// Build attempts to build a Helm chart with the given LocalReference and
// BuildOptions, writing it to p.
// It returns a Build describing the produced (or from cache observed) chart
// written to p, or a BuildError.
//
// The chart is loaded from the LocalReference.Path, and only packaged if the
// version (including BuildOptions.VersionMetadata modifications) differs from
// the current BuildOptions.CachedChart.
//
// BuildOptions.ValuesFiles changes are in this case not taken into account,
// and BuildOptions.Force should be used to enforce a rebuild.
//
// If the LocalReference.Path refers to an already packaged chart, and no
// packaging is required due to BuildOptions modifying the chart,
// LocalReference.Path is copied to p.
//
// If the LocalReference.Path refers to a chart directory, dependencies are
// confirmed to be present using the DependencyManager, while attempting to
// resolve any missing.
func (b *localChartBuilder) Build(ctx context.Context, ref Reference, p string, opts BuildOptions) (*Build, error) {
	localRef, ok := ref.(LocalReference)
	if !ok {
		err := fmt.Errorf("expected local chart reference")
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	if err := ref.Validate(); err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	// Load the chart metadata from the LocalReference to ensure it points
	// to a chart
	securePath, err := securejoin.SecureJoin(localRef.WorkDir, localRef.Path)
	if err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}
	curMeta, err := LoadChartMetadata(securePath)
	if err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}
	if err = curMeta.Validate(); err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	result := &Build{}
	result.Name = curMeta.Name

	// Set build specific metadata if instructed
	result.Version = curMeta.Version
	if opts.VersionMetadata != "" {
		ver, err := semver.NewVersion(curMeta.Version)
		if err != nil {
			err = fmt.Errorf("failed to parse version from chart metadata as SemVer: %w", err)
			return nil, &BuildError{Reason: ErrChartMetadataPatch, Err: err}
		}
		if *ver, err = ver.SetMetadata(opts.VersionMetadata); err != nil {
			err = fmt.Errorf("failed to set SemVer metadata on chart version: %w", err)
			return nil, &BuildError{Reason: ErrChartMetadataPatch, Err: err}
		}
		result.Version = ver.String()
	}

	isChartDir := pathIsDir(securePath)
	requiresPackaging := isChartDir || opts.VersionMetadata != "" || len(opts.GetValuesFiles()) != 0

	// If all the following is true, we do not need to package the chart:
	// - Chart name from cached chart matches resolved name
	// - Chart version from cached chart matches calculated version
	// - BuildOptions.Force is False
	if opts.CachedChart != "" && !opts.Force {
		if curMeta, err = LoadChartMetadataFromArchive(opts.CachedChart); err == nil {
			// If the cached metadata is corrupt, we ignore its existence
			// and continue the build
			if err = curMeta.Validate(); err == nil {
				if result.Name == curMeta.Name && result.Version == curMeta.Version {
					result.Path = opts.CachedChart
					result.ValuesFiles = opts.GetValuesFiles()
					result.Packaged = requiresPackaging

					return result, nil
				}
			}
		}
	}

	// If the chart at the path is already packaged and no custom values files
	// options are set, we can copy the chart without making modifications
	if !requiresPackaging {
		if err = copyFileToPath(securePath, p); err != nil {
			return result, &BuildError{Reason: ErrChartPull, Err: err}
		}
		result.Path = p
		return result, nil
	}

	// Merge chart values, if instructed
	var mergedValues map[string]interface{}
	if len(opts.GetValuesFiles()) > 0 {
		if mergedValues, err = mergeFileValues(localRef.WorkDir, opts.ValuesFiles); err != nil {
			return result, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
		}
	}

	// At this point we are certain we need to load the chart;
	// either to package it because it originates from a directory,
	// or because we have merged values and need to repackage
	loadedChart, err := secureloader.Load(localRef.WorkDir, localRef.Path)
	if err != nil {
		return result, &BuildError{Reason: ErrChartPackage, Err: err}
	}

	// Set earlier resolved version (with metadata)
	loadedChart.Metadata.Version = result.Version

	// Overwrite default values with merged values, if any
	if ok, err = OverwriteChartDefaultValues(loadedChart, mergedValues); ok || err != nil {
		if err != nil {
			return result, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
		}
		result.ValuesFiles = opts.GetValuesFiles()
	}

	// Ensure dependencies are fetched if building from a directory
	if isChartDir {
		if b.dm == nil {
			err = fmt.Errorf("local chart builder requires dependency manager for unpackaged charts")
			return result, &BuildError{Reason: ErrDependencyBuild, Err: err}
		}
		if result.ResolvedDependencies, err = b.dm.Build(ctx, ref, loadedChart); err != nil {
			return result, &BuildError{Reason: ErrDependencyBuild, Err: err}
		}
	}

	// Package the chart
	if err = packageToPath(loadedChart, p); err != nil {
		return result, &BuildError{Reason: ErrChartPackage, Err: err}
	}
	result.Path = p
	result.Packaged = requiresPackaging
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
		if f, err := os.Stat(secureP); err != nil || !f.Mode().IsRegular() {
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
