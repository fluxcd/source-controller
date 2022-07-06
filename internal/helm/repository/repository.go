/*
Copyright 2022 The Flux authors

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

package repository

import (
	"bytes"

	"helm.sh/helm/v3/pkg/repo"
)

// Downloader is used to download a chart from a remote Helm repository or OCI Helm repository.
type Downloader interface {
	// GetChartVersion returns the repo.ChartVersion for the given name and version
	// from the remote Helm repository or OCI Helm repository.
	GetChartVersion(name, version string) (*repo.ChartVersion, error)
	// DownloadChart downloads a chart from the remote Helm repository or OCI Helm repository.
	DownloadChart(chart *repo.ChartVersion) (*bytes.Buffer, error)
	// Clear removes all temporary files created by the downloader, caching the files if the cache is configured,
	// and calling garbage collector to remove unused files.
	Clear() error
}
