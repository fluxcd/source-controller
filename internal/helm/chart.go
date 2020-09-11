/*
Copyright 2020 The Flux CD contributors.

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
	"io"
	"os"
	"path"

	"helm.sh/helm/v3/pkg/chartutil"
)

// OverwriteChartDefaultValues overwrites the chart default values file in the
// given chartPath with the contents of the given valuesFile.
func OverwriteChartDefaultValues(chartPath, valuesFile string) error {
	if valuesFile == chartutil.ValuesfileName {
		return nil
	}
	srcPath := path.Join(chartPath, valuesFile)
	if f, err := os.Stat(srcPath); os.IsNotExist(err) || !f.Mode().IsRegular() {
		return fmt.Errorf("invalid values file path: %s", valuesFile)
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open values file '%s': %w", valuesFile, err)
	}
	defer src.Close()
	t, err := os.OpenFile(path.Join(chartPath, chartutil.ValuesfileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open values file '%s': %w", chartutil.ValuesfileName, err)
	}
	defer t.Close()
	if _, err := io.Copy(t, src); err != nil {
		return fmt.Errorf("failed to overwrite default values with '%s': %w", valuesFile, err)
	}
	return nil
}
