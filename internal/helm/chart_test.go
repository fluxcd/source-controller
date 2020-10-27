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
	"reflect"
	"strings"
	"testing"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

var (
	originalValuesFixture []byte            = []byte("override: original")
	overrideValuesFixture []byte            = []byte("override: test")
	chartFilesFixture     []*helmchart.File = []*helmchart.File{
		{
			Name: "values.yaml",
			Data: originalValuesFixture,
		},
		{
			Name: "values-identical.yaml",
			Data: originalValuesFixture,
		},
		{
			Name: "values-override.yaml",
			Data: overrideValuesFixture,
		},
		{
			Name: "values-invalid.yaml",
			Data: []byte(":fail!"),
		},
	}
	chartFixture helmchart.Chart = helmchart.Chart{
		Metadata: &helmchart.Metadata{
			Name:    "test",
			Version: "0.1.0",
		},
		Raw:   chartFilesFixture,
		Files: chartFilesFixture,
	}
)

func TestOverwriteChartDefaultValues(t *testing.T) {
	for _, tt := range []string{"", "values.yaml", "values-identical.yaml"} {
		t.Run(tt, func(t *testing.T) {
			fixture := chartFixture
			ok, err := OverwriteChartDefaultValues(&fixture, tt)
			if ok {
				t.Error("OverwriteChartDefaultValues() should return false")
				return
			}
			if err != nil {
				t.Errorf("OverwriteChartDefaultValues() error = %v", err)
				return
			}
			for _, f := range fixture.Raw {
				if f.Name == chartutil.ValuesfileName && !reflect.DeepEqual(f.Data, originalValuesFixture) {
					t.Error("OverwriteChartDefaultValues() should not override values.yaml in Raw field")
					return
				}
			}
			for _, f := range fixture.Files {
				if f.Name == chartutil.ValuesfileName && !reflect.DeepEqual(f.Data, originalValuesFixture) {
					t.Error("OverwriteChartDefaultValues() should not override values.yaml in Files field")
					return
				}
			}
		})
	}

	t.Run("values-error.yaml", func(t *testing.T) {
		fixture := chartFixture
		ok, err := OverwriteChartDefaultValues(&fixture, "values-error.yaml")
		if ok {
			t.Error("OverwriteChartDefaultValues() should return false")
		}
		if err == nil {
			t.Error("OverwriteChartDefaultValues() expects an error")
			return
		} else if !strings.Contains(err.Error(), "failed to locate override values file") {
			t.Error("OverwriteChartDefaultValues() returned invalid error")
			return
		}
	})

	t.Run("values-override.yaml", func(t *testing.T) {
		fixture := chartFixture
		ok, err := OverwriteChartDefaultValues(&fixture, "values-override.yaml")
		if err != nil {
			t.Errorf("OverwriteChartDefaultValues() error = %v", err)
			return
		}
		if !ok {
			t.Error("OverwriteChartDefaultValues() should return true")
			return
		}
		for _, f := range fixture.Raw {
			if f.Name == chartutil.ValuesfileName && string(f.Data) != string(overrideValuesFixture) {
				t.Error("OverwriteChartDefaultValues() should override values.yaml in Raw field")
				return
			}
		}
		for _, f := range fixture.Files {
			if f.Name == chartutil.ValuesfileName && string(f.Data) != string(overrideValuesFixture) {
				t.Error("OverwriteChartDefaultValues() should override values.yaml in Files field")
				return
			}
		}

		// Context: the impossible chart, no values.yaml file defined!
		fixture.Raw = fixture.Raw[1:]
		fixture.Files = fixture.Files[1:]
		ok, err = OverwriteChartDefaultValues(&fixture, "values-override.yaml")
		if ok {
			t.Error("OverwriteChartDefaultValues() should return false")
			return
		}
		if err == nil {
			t.Error("OverwriteChartDefaultValues() expects an error")
			return
		} else if !strings.Contains(err.Error(), "failed to locate values file") {
			t.Error("OverwriteChartDefaultValues() returned invalid error")
			return
		}
	})

	t.Run("values-invalid.yaml", func(t *testing.T) {
		fixture := chartFixture
		fixture.Raw[0].Data = fixture.Raw[1].Data
		fixture.Files[0].Data = fixture.Files[1].Data
		ok, err := OverwriteChartDefaultValues(&fixture, "values-invalid.yaml")
		if ok {
			t.Error("OverwriteChartDefaultValues() should return false")
			return
		}
		if err == nil {
			t.Error("OverwriteChartDefaultValues() expects an error")
			return
		} else if !strings.Contains(err.Error(), "failed to parse override values file") {
			t.Error("OverwriteChartDefaultValues() returned invalid error")
			return
		}
	})
}
