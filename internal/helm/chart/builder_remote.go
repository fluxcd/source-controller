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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"github.com/fluxcd/source-controller/internal/helm/repository"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/pkg/runtime/transform"

	"github.com/fluxcd/source-controller/internal/fs"
	"github.com/fluxcd/source-controller/internal/helm/chart/secureloader"
)

// Remote is a repository.ChartRepository or a repository.OCIChartRepository.
// It is used to download a chart from a remote Helm repository or OCI registry.
type Remote interface {
	// GetChart returns a chart.Chart from the remote repository.
	Get(name, version string) (*repo.ChartVersion, error)
	// GetChartVersion returns a chart.ChartVersion from the remote repository.
	DownloadChart(chart *repo.ChartVersion) (*bytes.Buffer, error)
}

type remoteChartBuilder struct {
	remote Remote
}

// NewRemoteBuilder returns a Builder capable of building a Helm
// chart with a RemoteReference in the given repository.ChartRepository.
func NewRemoteBuilder(repository Remote) Builder {
	return &remoteChartBuilder{
		remote: repository,
	}
}

// Build attempts to build a Helm chart with the given RemoteReference and
// BuildOptions, writing it to p.
// It returns a Build describing the produced (or from cache observed) chart
// written to p, or a BuildError.
//
// The latest version for the RemoteReference.Version is determined in the
// repository.ChartRepository, only downloading it if the version (including
// BuildOptions.VersionMetadata) differs from the current BuildOptions.CachedChart.
// BuildOptions.ValuesFiles changes are in this case not taken into account,
// and BuildOptions.Force should be used to enforce a rebuild.
//
// After downloading the chart, it is only packaged if required due to BuildOptions
// modifying the chart, otherwise the exact data as retrieved from the repository
// is written to p, after validating it to be a chart.
func (b *remoteChartBuilder) Build(_ context.Context, ref Reference, p string, opts BuildOptions) (*Build, error) {
	remoteRef, ok := ref.(RemoteReference)
	if !ok {
		err := fmt.Errorf("expected remote chart reference")
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	if err := ref.Validate(); err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	var (
		res *bytes.Buffer
		err error
	)

	result := &Build{}
	switch b.remote.(type) {
	case *repository.ChartRepository:
		res, err = b.downloadFromRepository(b.remote.(*repository.ChartRepository), remoteRef, result, opts)
		if err != nil {
			return nil, &BuildError{Reason: ErrChartPull, Err: err}
		}
		if res == nil {
			return result, nil
		}
	case *repository.OCIChartRepository:
		res, err = b.downloadFromOCIRepository(b.remote.(*repository.OCIChartRepository), remoteRef, result, opts)
		if err != nil {
			return nil, &BuildError{Reason: ErrChartPull, Err: err}
		}
		if res == nil {
			return result, nil
		}
	default:
		return nil, &BuildError{Reason: ErrChartReference, Err: fmt.Errorf("unsupported remote type %T", b.remote)}
	}

	requiresPackaging := len(opts.GetValuesFiles()) != 0 || opts.VersionMetadata != ""

	// Use literal chart copy from remote if no custom values files options are
	// set or version metadata isn't set.
	if !requiresPackaging {
		if err = validatePackageAndWriteToPath(res, p); err != nil {
			return nil, &BuildError{Reason: ErrChartPull, Err: err}
		}
		result.Path = p
		return result, nil
	}

	// Load the chart and merge chart values
	var chart *helmchart.Chart
	if chart, err = secureloader.LoadArchive(res); err != nil {
		err = fmt.Errorf("failed to load downloaded chart: %w", err)
		return result, &BuildError{Reason: ErrChartPackage, Err: err}
	}
	chart.Metadata.Version = result.Version

	mergedValues, err := mergeChartValues(chart, opts.ValuesFiles)
	if err != nil {
		err = fmt.Errorf("failed to merge chart values: %w", err)
		return result, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
	}
	// Overwrite default values with merged values, if any
	if ok, err = OverwriteChartDefaultValues(chart, mergedValues); ok || err != nil {
		if err != nil {
			return nil, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
		}
		result.ValuesFiles = opts.GetValuesFiles()
	}

	// Package the chart with the custom values
	if err = packageToPath(chart, p); err != nil {
		return nil, &BuildError{Reason: ErrChartPackage, Err: err}
	}
	result.Path = p
	result.Packaged = true
	return result, nil
}

func (b *remoteChartBuilder) downloadFromOCIRepository(remote *repository.OCIChartRepository, remoteRef RemoteReference, buildResult *Build, opts BuildOptions) (*bytes.Buffer, error) {
	cv, err := remote.Get(remoteRef.Name, remoteRef.Version)
	if err != nil {
		err = fmt.Errorf("failed to get chart version for remote reference: %w", err)
		return nil, &BuildError{Reason: ErrChartPull, Err: err}
	}

	result, shouldReturn, err := generateBuildResult(cv, opts)
	if err != nil {
		return nil, err
	}

	if shouldReturn {
		*buildResult = *result
		return nil, nil
	}

	// Download the package for the resolved version
	res, err := remote.DownloadChart(cv)
	if err != nil {
		err = fmt.Errorf("failed to download chart for remote reference: %w", err)
		return nil, &BuildError{Reason: ErrChartPull, Err: err}
	}

	*buildResult = *result

	return res, nil
}

func (b *remoteChartBuilder) downloadFromRepository(remote *repository.ChartRepository, remoteRef RemoteReference, buildResult *Build, opts BuildOptions) (*bytes.Buffer, error) {
	if err := remote.StrategicallyLoadIndex(); err != nil {
		err = fmt.Errorf("could not load repository index for remote chart reference: %w", err)
		return nil, &BuildError{Reason: ErrChartPull, Err: err}
	}
	defer remote.Unload()

	// Get the current version for the RemoteReference
	cv, err := remote.Get(remoteRef.Name, remoteRef.Version)
	if err != nil {
		err = fmt.Errorf("failed to get chart version for remote reference: %w", err)
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	result, shouldReturn, err := generateBuildResult(cv, opts)
	if err != nil {
		return nil, err
	}

	if shouldReturn {
		*buildResult = *result
		return nil, nil
	}

	// Download the package for the resolved version
	res, err := remote.DownloadChart(cv)
	if err != nil {
		err = fmt.Errorf("failed to download chart for remote reference: %w", err)
		return nil, &BuildError{Reason: ErrChartPull, Err: err}
	}

	*buildResult = *result

	return res, nil
}

func generateBuildResult(cv *repo.ChartVersion, opts BuildOptions) (*Build, bool, error) {
	result := &Build{}
	result.Version = cv.Version
	result.Name = cv.Name

	// Set build specific metadata if instructed
	if opts.VersionMetadata != "" {
		ver, err := setBuildMetaData(result.Version, opts.VersionMetadata)
		if err != nil {
			return nil, false, &BuildError{Reason: ErrChartMetadataPatch, Err: err}
		}
		result.Version = ver.String()
	}

	requiresPackaging := len(opts.GetValuesFiles()) != 0 || opts.VersionMetadata != ""

	// If all the following is true, we do not need to download and/or build the chart:
	// - Chart name from cached chart matches resolved name
	// - Chart version from cached chart matches calculated version
	// - BuildOptions.Force is False
	if opts.CachedChart != "" && !opts.Force {
		if curMeta, err := LoadChartMetadataFromArchive(opts.CachedChart); err == nil {
			// If the cached metadata is corrupt, we ignore its existence
			// and continue the build
			if err = curMeta.Validate(); err == nil {
				if result.Name == curMeta.Name && result.Version == curMeta.Version {
					result.Path = opts.CachedChart
					result.ValuesFiles = opts.GetValuesFiles()
					result.Packaged = requiresPackaging
					return result, true, nil
				}
			}
		}
	}

	return result, false, nil
}

func setBuildMetaData(version, versionMetadata string) (*semver.Version, error) {
	ver, err := semver.NewVersion(version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version from chart metadata as SemVer: %w", err)
	}
	if *ver, err = ver.SetMetadata(versionMetadata); err != nil {
		return nil, fmt.Errorf("failed to set SemVer metadata on chart version: %w", err)
	}

	return ver, nil
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

// validatePackageAndWriteToPath atomically writes the packaged chart from reader
// to out while validating it by loading the chart metadata from the archive.
func validatePackageAndWriteToPath(reader io.Reader, out string) error {
	tmpFile, err := os.CreateTemp("", filepath.Base(out))
	if err != nil {
		return fmt.Errorf("failed to create temporary file for chart: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err = tmpFile.ReadFrom(reader); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write chart to file: %w", err)
	}
	if err = tmpFile.Close(); err != nil {
		return err
	}
	meta, err := LoadChartMetadataFromArchive(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("failed to load chart metadata from written chart: %w", err)
	}
	if err = meta.Validate(); err != nil {
		return fmt.Errorf("failed to validate metadata of written chart: %w", err)
	}
	if err = fs.RenameWithFallback(tmpFile.Name(), out); err != nil {
		return fmt.Errorf("failed to write chart to file: %w", err)
	}
	return nil
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
