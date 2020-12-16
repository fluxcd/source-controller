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
	"testing"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

var (
	originalValuesFixture []byte            = []byte("override: original")
	chartFilesFixture     []*helmchart.File = []*helmchart.File{
		{
			Name: "values.yaml",
			Data: originalValuesFixture,
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
	invalidChartFixture := chartFixture
	invalidChartFixture.Raw = []*helmchart.File{}
	invalidChartFixture.Files = []*helmchart.File{}

	testCases := []struct {
		desc      string
		chart     helmchart.Chart
		data      []byte
		ok        bool
		expectErr bool
	}{
		{
			desc:      "invalid chart",
			chart:     invalidChartFixture,
			data:      originalValuesFixture,
			expectErr: true,
		},
		{
			desc:  "identical override",
			chart: chartFixture,
			data:  originalValuesFixture,
		},
		{
			desc:  "valid override",
			chart: chartFixture,
			ok:    true,
			data:  []byte("override: test"),
		},
		{
			desc:  "empty override",
			chart: chartFixture,
			ok:    true,
			data:  []byte(""),
		},
		{
			desc:      "invalid",
			chart:     chartFixture,
			data:      []byte("!fail:"),
			expectErr: true,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			fixture := tt.chart
			ok, err := OverwriteChartDefaultValues(&fixture, tt.data)
			if ok != tt.ok {
				t.Fatalf("should return %v, returned %v", tt.ok, ok)
			}
			if err != nil && !tt.expectErr {
				t.Fatalf("returned unexpected error: %v", err)
			}
			if err == nil && tt.expectErr {
				t.Fatal("expected error")
			}

			for _, f := range fixture.Raw {
				if f.Name == chartutil.ValuesfileName && reflect.DeepEqual(f.Data, originalValuesFixture) && tt.ok {
					t.Error("should override values.yaml in Raw field")
				}
			}
			for _, f := range fixture.Files {
				if f.Name == chartutil.ValuesfileName && reflect.DeepEqual(f.Data, originalValuesFixture) && tt.ok {
					t.Error("should override values.yaml in Files field")
				}
			}
		})
	}
}
