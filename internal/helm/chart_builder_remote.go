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
	"io"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
	"github.com/fluxcd/pkg/runtime/transform"
	"github.com/fluxcd/source-controller/internal/fs"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"sigs.k8s.io/yaml"
)

type remoteChartBuilder struct {
	remote *ChartRepository
}

// NewRemoteChartBuilder returns a ChartBuilder capable of building a Helm
// chart with a RemoteChartReference from the given ChartRepository.
func NewRemoteChartBuilder(repository *ChartRepository) ChartBuilder {
	return &remoteChartBuilder{
		remote: repository,
	}
}

func (b *remoteChartBuilder) Build(_ context.Context, ref ChartReference, p string, opts BuildOptions) (*ChartBuild, error) {
	remoteRef, ok := ref.(RemoteChartReference)
	if !ok {
		return nil, fmt.Errorf("expected remote chart reference")
	}

	if err := ref.Validate(); err != nil {
		return nil, err
	}

	if err := b.remote.LoadFromCache(); err != nil {
		return nil, fmt.Errorf("could not load repository index for remote chart reference: %w", err)
	}
	defer b.remote.Unload()

	// Get the current version for the RemoteChartReference
	cv, err := b.remote.Get(remoteRef.Name, remoteRef.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get chart version for remote reference: %w", err)
	}

	result := &ChartBuild{}
	result.Name = cv.Name
	result.Version = cv.Version
	// Set build specific metadata if instructed
	if opts.VersionMetadata != "" {
		ver, err := semver.NewVersion(result.Version)
		if err != nil {
			return nil, err
		}
		if *ver, err = ver.SetMetadata(opts.VersionMetadata); err != nil {
			return nil, err
		}
		result.Version = ver.String()
	}

	// If all the following is true, we do not need to download and/or build the chart:
	//	Chart version from metadata matches chart version for ref
	//  BuildOptions.Force is False
	if opts.CachedChart != "" && !opts.Force {
		if curMeta, err := LoadChartMetadataFromArchive(opts.CachedChart); err == nil && result.Version == curMeta.Version {
			result.Path = opts.CachedChart
			result.ValueFiles = opts.GetValueFiles()
			return result, nil
		}
	}

	// Download the package for the resolved version
	res, err := b.remote.DownloadChart(cv)
	if err != nil {
		return nil, fmt.Errorf("failed to download chart for remote reference: %w", err)
	}

	// Use literal chart copy from remote if no custom value files options are set
	if len(opts.GetValueFiles()) == 0 {
		if err = validatePackageAndWriteToPath(res, p); err != nil {
			return nil, err
		}
		result.Path = p
		return result, nil
	}

	// Load the chart and merge chart values
	var chart *helmchart.Chart
	if chart, err = loader.LoadArchive(res); err != nil {
		return nil, fmt.Errorf("failed to load downloaded chart: %w", err)
	}

	mergedValues, err := mergeChartValues(chart, opts.ValueFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to merge chart values: %w", err)
	}
	// Overwrite default values with merged values, if any
	if ok, err = OverwriteChartDefaultValues(chart, mergedValues); ok || err != nil {
		if err != nil {
			return nil, err
		}
		result.ValueFiles = opts.GetValueFiles()
	}

	// Package the chart with the custom values
	if err = packageToPath(chart, p); err != nil {
		return nil, err
	}
	result.Path = p
	result.Packaged = true
	return result, nil
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
	if _, err = LoadChartMetadataFromArchive(tmpFile.Name()); err != nil {
		return fmt.Errorf("failed to load chart metadata from written chart: %w", err)
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
