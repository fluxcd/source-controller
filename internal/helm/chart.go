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
	"fmt"
	"reflect"

	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

// OverwriteChartDefaultValues overwrites the chart default values file with the
// contents of the given valuesFile.
func OverwriteChartDefaultValues(chart *helmchart.Chart, valuesFile string) (bool, error) {
	if valuesFile == "" || valuesFile == chartutil.ValuesfileName {
		return false, nil
	}

	// Find override file and retrieve contents
	var valuesData []byte
	for _, f := range chart.Files {
		if f.Name == valuesFile {
			valuesData = f.Data
			break
		}
	}
	if valuesData == nil {
		return false, fmt.Errorf("failed to locate override values file: %s", valuesFile)
	}

	// Read override values file data
	values, err := chartutil.ReadValues(valuesData)
	if err != nil {
		return false, fmt.Errorf("failed to parse override values file: %s", valuesFile)
	}

	// Replace current values file in Raw field
	for _, f := range chart.Raw {
		if f.Name == chartutil.ValuesfileName {
			// Do nothing if contents are equal
			if reflect.DeepEqual(f.Data, valuesData) {
				return false, nil
			}

			// Replace in Files field
			for _, f := range chart.Files {
				if f.Name == chartutil.ValuesfileName {
					f.Data = valuesData
				}
			}

			f.Data = valuesData
			chart.Values = values
			return true, nil
		}
	}

	// This should never happen, helm charts must have a values.yaml file to be valid
	return false, fmt.Errorf("failed to locate values file: %s", chartutil.ValuesfileName)
}
