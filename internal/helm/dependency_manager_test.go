/*
Copyright 2020 The Flux authors

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
	"testing"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/repo"
)

var (
	// helmPackageFile contains the path to a Helm package in the v2 format
	// without any dependencies
	helmPackageFile      = "testdata/charts/helmchart-0.1.0.tgz"
	chartName            = "helmchart"
	chartVersion         = "0.1.0"
	chartLocalRepository = "file://../helmchart"
	remoteDepFixture     = helmchart.Dependency{
		Name:       chartName,
		Version:    chartVersion,
		Repository: "https://example.com/charts",
	}
	// helmPackageV1File contains the path to a Helm package in the v1 format,
	// including dependencies in a requirements.yaml file which should be
	// loaded
	helmPackageV1File = "testdata/charts/helmchartwithdeps-v1-0.3.0.tgz"
	chartNameV1       = "helmchartwithdeps-v1"
	chartVersionV1    = "0.3.0"
)

func TestBuild_WithEmptyDependencies(t *testing.T) {
	dm := DependencyManager{
		Dependencies: nil,
	}
	if err := dm.Build(context.TODO()); err != nil {
		t.Errorf("Build() should return nil")
	}
}

func TestBuild_WithLocalChart(t *testing.T) {
	tests := []struct {
		name    string
		dep     helmchart.Dependency
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid path",
			dep: helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: chartLocalRepository,
			},
		},
		{
			name: "valid path",
			dep: helmchart.Dependency{
				Name:       chartName,
				Alias:      "aliased",
				Version:    chartVersion,
				Repository: chartLocalRepository,
			},
		},
		{
			name: "allowed traversing path",
			dep: helmchart.Dependency{
				Name:       chartName,
				Alias:      "aliased",
				Version:    chartVersion,
				Repository: "file://../../../testdata/charts/helmchartwithdeps/../helmchart",
			},
		},
		{
			name: "invalid path",
			dep: helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "file://../invalid",
			},
			wantErr: true,
			errMsg:  "no chart found at",
		},
		{
			name: "illegal traversing path",
			dep: helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: "file://../../../../../controllers/testdata/charts/helmchart",
			},
			wantErr: true,
			errMsg:  "no chart found at",
		},
		{
			name: "invalid version constraint format",
			dep: helmchart.Dependency{
				Name:       chartName,
				Version:    "!2.0",
				Repository: chartLocalRepository,
			},
			wantErr: true,
			errMsg:  "has an invalid version/constraint format",
		},
		{
			name: "invalid version",
			dep: helmchart.Dependency{
				Name:       chartName,
				Version:    chartVersion,
				Repository: chartLocalRepository,
			},
			wantErr: true,
			errMsg:  "can't get a valid version for dependency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := chartFixture
			dm := DependencyManager{
				WorkingDir: "./",
				ChartPath:  "testdata/charts/helmchart",
				Chart:      &c,
				Dependencies: []*DependencyWithRepository{
					{
						Dependency: &tt.dep,
						Repository: nil,
					},
				},
			}

			err := dm.Build(context.TODO())
			deps := dm.Chart.Dependencies()

			if (err != nil) && tt.wantErr {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Build() expected to return error: %s, got: %s", tt.errMsg, err)
				}
				if len(deps) > 0 {
					t.Fatalf("chart expected to have no dependencies registered")
				}
				return
			} else if err != nil {
				t.Errorf("Build() not expected to return an error: %s", err)
				return
			}

			if len(deps) == 0 {
				t.Fatalf("chart expected to have at least one dependency registered")
			}
			if deps[0].Metadata.Name != chartName {
				t.Errorf("chart dependency has incorrect name, expected: %s, got: %s", chartName, deps[0].Metadata.Name)
			}
			if deps[0].Metadata.Version != chartVersion {
				t.Errorf("chart dependency has incorrect version, expected: %s, got: %s", chartVersion, deps[0].Metadata.Version)
			}
		})
	}
}

func TestBuild_WithRemoteChart(t *testing.T) {
	chart := chartFixture
	b, err := os.ReadFile(helmPackageFile)
	if err != nil {
		t.Fatal(err)
	}
	i := repo.NewIndexFile()
	i.MustAdd(&helmchart.Metadata{Name: chartName, Version: chartVersion}, fmt.Sprintf("%s-%s.tgz", chartName, chartVersion), "http://example.com/charts", "sha256:1234567890")
	mg := mockGetter{response: b}
	cr := newChartRepository()
	cr.URL = remoteDepFixture.Repository
	cr.Index = i
	cr.Client = &mg
	dm := DependencyManager{
		Chart: &chart,
		Dependencies: []*DependencyWithRepository{
			{
				Dependency: &remoteDepFixture,
				Repository: cr,
			},
		},
	}

	if err := dm.Build(context.TODO()); err != nil {
		t.Errorf("Build() expected to not return error: %s", err)
	}

	deps := dm.Chart.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("chart expected to have one dependency registered")
	}
	if deps[0].Metadata.Name != chartName {
		t.Errorf("chart dependency has incorrect name, expected: %s, got: %s", chartName, deps[0].Metadata.Name)
	}
	if deps[0].Metadata.Version != chartVersion {
		t.Errorf("chart dependency has incorrect version, expected: %s, got: %s", chartVersion, deps[0].Metadata.Version)
	}

	// When repo is not set
	dm.Dependencies[0].Repository = nil
	if err := dm.Build(context.TODO()); err == nil {
		t.Errorf("Build() expected to return error")
	} else if !strings.Contains(err.Error(), "is not a local chart reference") {
		t.Errorf("Build() expected to return different error, got: %s", err)
	}
}
