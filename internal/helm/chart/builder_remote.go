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
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"

	sourcefs "github.com/fluxcd/pkg/oci"
	"github.com/fluxcd/pkg/runtime/transform"

	"github.com/werf/nelm-source-controller/internal/helm/chart/secureloader"
	"github.com/werf/nelm-source-controller/internal/helm/repository"
	"github.com/werf/nelm-source-controller/internal/oci"
)

type remoteChartBuilder struct {
	remote repository.Downloader
}

// NewRemoteBuilder returns a Builder capable of building a Helm
// chart with a RemoteReference in the given repository.Downloader.
func NewRemoteBuilder(repository repository.Downloader) Builder {
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
func (b *remoteChartBuilder) Build(ctx context.Context, ref Reference, p string, opts BuildOptions) (*Build, error) {
	remoteRef, ok := ref.(RemoteReference)
	if !ok {
		err := fmt.Errorf("expected remote chart reference")
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	if err := ref.Validate(); err != nil {
		return nil, &BuildError{Reason: ErrChartReference, Err: err}
	}

	res, result, err := b.downloadFromRepository(ctx, b.remote, remoteRef, opts)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return result, nil
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

	mergedValues, valuesFiles, err := mergeChartValues(chart, opts.ValuesFiles, opts.IgnoreMissingValuesFiles)
	if err != nil {
		err = fmt.Errorf("failed to merge chart values: %w", err)
		return result, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
	}
	// Overwrite default values with merged values, if any
	if ok, err = OverwriteChartDefaultValues(chart, mergedValues); ok || err != nil {
		if err != nil {
			return nil, &BuildError{Reason: ErrValuesFilesMerge, Err: err}
		}
		result.ValuesFiles = valuesFiles
	}

	// Package the chart with the custom values
	if err = packageToPath(chart, p); err != nil {
		return nil, &BuildError{Reason: ErrChartPackage, Err: err}
	}
	result.Path = p
	result.Packaged = true
	return result, nil
}

func (b *remoteChartBuilder) downloadFromRepository(ctx context.Context, remote repository.Downloader, remoteRef RemoteReference, opts BuildOptions) (*bytes.Buffer, *Build, error) {
	// Get the current version for the RemoteReference
	cv, err := remote.GetChartVersion(remoteRef.Name, remoteRef.Version)
	if err != nil {
		var reason BuildErrorReason
		switch err.(type) {
		case *repository.ErrReference:
			reason = ErrChartReference
		case *repository.ErrExternal:
			reason = ErrChartPull
		default:
			reason = ErrUnknown
		}
		err = fmt.Errorf("failed to get chart version for remote reference: %w", err)
		return nil, nil, &BuildError{Reason: reason, Err: err}
	}

	verifiedResult := oci.VerificationResultIgnored

	// Verify the chart if necessary
	if opts.Verify {
		if verifiedResult, err = remote.VerifyChart(ctx, cv); err != nil {
			return nil, nil, &BuildError{Reason: ErrChartVerification, Err: err}
		}
	}

	result, shouldReturn, err := generateBuildResult(cv, opts)
	if err != nil {
		return nil, nil, err
	}

	result.VerifiedResult = verifiedResult

	if shouldReturn {
		return nil, result, nil
	}

	// Download the package for the resolved version
	res, err := remote.DownloadChart(cv)
	if err != nil {
		err = fmt.Errorf("failed to download chart for remote reference: %w", err)
		return nil, nil, &BuildError{Reason: ErrChartPull, Err: err}
	}

	return res, result, nil
}

// generateBuildResult returns a Build object generated from the given chart version and build options. It also returns
// true if the given chart can be retrieved from cache and doesn't need to be downloaded again.
func generateBuildResult(cv *repo.ChartVersion, opts BuildOptions) (*Build, bool, error) {
	result := &Build{}
	result.Version = cv.Version
	result.Name = cv.Name
	result.VerifiedResult = oci.VerificationResultIgnored

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
					if opts.CachedChartValuesFiles != nil {
						// If the cached chart values files are set, we should use them
						// instead of reporting the values files.
						result.ValuesFiles = opts.CachedChartValuesFiles
					}
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
// By default, a missing file is considered an error. If ignoreMissing is set true,
// missing files are ignored.
// It returns the merge result and the list of files that contributed to that result,
// or an error.
func mergeChartValues(chart *helmchart.Chart, paths []string, ignoreMissing bool) (map[string]interface{}, []string, error) {
	mergedValues := make(map[string]interface{})
	valuesFiles := make([]string, 0, len(paths))
	for _, p := range paths {
		cfn := filepath.Clean(p)
		if cfn == chartutil.ValuesfileName {
			mergedValues = transform.MergeMaps(mergedValues, chart.Values)
			valuesFiles = append(valuesFiles, p)
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
			if ignoreMissing {
				continue
			}
			return nil, nil, fmt.Errorf("no values file found at path '%s'", p)
		}
		values := make(map[string]interface{})
		if err := yaml.Unmarshal(b, &values); err != nil {
			return nil, nil, fmt.Errorf("unmarshaling values from '%s' failed: %w", p, err)
		}
		mergedValues = transform.MergeMaps(mergedValues, values)
		valuesFiles = append(valuesFiles, p)
	}
	return mergedValues, valuesFiles, nil
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
	if err = sourcefs.RenameWithFallback(tmpFile.Name(), out); err != nil {
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
