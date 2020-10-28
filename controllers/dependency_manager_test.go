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

package controllers

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/fluxcd/source-controller/internal/helm"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
)

var (
	helmPackageFile = "testdata/charts/helmchart-0.1.0.tgz"

	localDepFixture helmchart.Dependency = helmchart.Dependency{
		Name:       "helmchart",
		Version:    "0.1.0",
		Repository: "file://../helmchart",
	}
	remoteDepFixture helmchart.Dependency = helmchart.Dependency{
		Name:       "helmchart",
		Version:    "0.1.0",
		Repository: "https://example.com/charts",
	}
	chartFixture helmchart.Chart = helmchart.Chart{
		Metadata: &helmchart.Metadata{
			Name: "test",
		},
	}
)

func TestBuild_WithEmptyDependencies(t *testing.T) {
	dm := DependencyManager{
		Dependencies: nil,
	}
	if err := dm.Build(); err != nil {
		t.Errorf("Build() should return nil")
	}
}

func TestBuild_WithLocalChart(t *testing.T) {
	loc := localDepFixture
	chart := chartFixture
	dm := DependencyManager{
		Chart:     &chart,
		ChartPath: "testdata/charts/helmchart",
		Dependencies: []*DependencyWithRepository{
			{
				Dependency: &loc,
				Repo:       nil,
			},
		},
	}

	if err := dm.Build(); err != nil {
		t.Errorf("Build() expected to not return error: %s", err)
	}

	deps := dm.Chart.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("chart expected to have one dependency registered")
	}
	if deps[0].Metadata.Name != localDepFixture.Name {
		t.Errorf("chart dependency has incorrect name, expected: %s, got: %s", localDepFixture.Name, deps[0].Metadata.Name)
	}
	if deps[0].Metadata.Version != localDepFixture.Version {
		t.Errorf("chart dependency has incorrect version, expected: %s, got: %s", localDepFixture.Version, deps[0].Metadata.Version)
	}

	tests := []struct {
		name        string
		dep         helmchart.Dependency
		expectError string
	}{
		{
			name: "invalid path",
			dep: helmchart.Dependency{
				Name:       "helmchart",
				Version:    "0.1.0",
				Repository: "file://../invalid",
			},
			expectError: "no such file or directory",
		},
		{
			name: "invalid version constraint format",
			dep: helmchart.Dependency{
				Name:       "helmchart",
				Version:    "!2.0",
				Repository: "file://../helmchart",
			},
			expectError: "has an invalid version/constraint format",
		},
		{
			name: "invalid version",
			dep: helmchart.Dependency{
				Name:       "helmchart",
				Version:    "1.0.0",
				Repository: "file://../helmchart",
			},
			expectError: "can't get a valid version for dependency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := chartFixture
			dm = DependencyManager{
				Chart:     &c,
				ChartPath: "testdata/charts/helmchart",
				Dependencies: []*DependencyWithRepository{
					{
						Dependency: &tt.dep,
						Repo:       nil,
					},
				},
			}

			if err := dm.Build(); err == nil {
				t.Errorf("Build() expected to return error")
			} else if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("Build() expected to return error: %s, got: %s", tt.expectError, err)
			}
			if len(dm.Chart.Dependencies()) > 0 {
				t.Fatalf("chart expected to have no dependencies registered")
			}
		})
	}
}

func TestBuild_WithRemoteChart(t *testing.T) {
	chart := chartFixture
	b, err := ioutil.ReadFile(helmPackageFile)
	if err != nil {
		t.Fatal(err)
	}
	i := repo.NewIndexFile()
	i.Add(&helmchart.Metadata{Name: "helmchart", Version: "0.1.0"}, "helmchart-0.1.0.tgz", "http://example.com/charts", "sha256:1234567890")
	mg := mockGetter{response: b}
	cr := &helm.ChartRepository{
		URL:    remoteDepFixture.Repository,
		Index:  i,
		Client: &mg,
	}
	dm := DependencyManager{
		Chart: &chart,
		Dependencies: []*DependencyWithRepository{
			{
				Dependency: &remoteDepFixture,
				Repo:       cr,
			},
		},
	}

	if err := dm.Build(); err != nil {
		t.Errorf("Build() expected to not return error: %s", err)
	}

	deps := dm.Chart.Dependencies()
	if len(deps) != 1 {
		t.Fatalf("chart expected to have one dependency registered")
	}
	if deps[0].Metadata.Name != remoteDepFixture.Name {
		t.Errorf("chart dependency has incorrect name, expected: %s, got: %s", remoteDepFixture.Name, deps[0].Metadata.Name)
	}
	if deps[0].Metadata.Version != remoteDepFixture.Version {
		t.Errorf("chart dependency has incorrect version, expected: %s, got: %s", remoteDepFixture.Version, deps[0].Metadata.Version)
	}

	// When repo is not set
	dm.Dependencies[0].Repo = nil
	if err := dm.Build(); err == nil {
		t.Errorf("Build() expected to return error")
	} else if !strings.Contains(err.Error(), "chartrepo should not be nil") {
		t.Errorf("Build() expected to return different error, got: %s", err)
	}
}

type mockGetter struct {
	response []byte
}

func (g *mockGetter) Get(url string, options ...getter.Option) (*bytes.Buffer, error) {
	return bytes.NewBuffer(g.response), nil
}
