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
	"io/ioutil"

	"github.com/blang/semver"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"
)

func GetDownloadableChartVersionFromIndex(path, chart, version string) (*repo.ChartVersion, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Helm repository index file: %w", err)
	}
	index := &repo.IndexFile{}
	if err := yaml.Unmarshal(b, index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Helm repository index file: %w", err)
	}

	var cv *repo.ChartVersion
	if version == "" || version == "*" {
		cv, err = index.Get(chart, version)
		if err != nil {
			if err == repo.ErrNoChartName {
				err = fmt.Errorf("chart '%s' could not be found in Helm repository index", chart)
			}
			return nil, err
		}
	} else {
		entries, ok := index.Entries[chart]
		if !ok {
			return nil, fmt.Errorf("chart '%s' could not be found in Helm repository index", chart)
		}

		rng, err := semver.ParseRange(version)
		if err != nil {
			return nil, fmt.Errorf("semver range parse error: %w", err)
		}
		versionEntryLookup := make(map[string]*repo.ChartVersion)
		var versionsInRange []semver.Version
		for _, e := range entries {
			v, _ := semver.ParseTolerant(e.Version)
			if rng(v) {
				versionsInRange = append(versionsInRange, v)
				versionEntryLookup[v.String()] = e
			}
		}
		if len(versionsInRange) == 0 {
			return nil, fmt.Errorf("no match found for semver: %s", version)
		}
		semver.Sort(versionsInRange)

		latest := versionsInRange[len(versionsInRange)-1]
		cv = versionEntryLookup[latest.String()]
	}

	if len(cv.URLs) == 0 {
		return nil, fmt.Errorf("no downloadable URLs for chart '%s' with version '%s'", cv.Name, cv.Version)
	}

	return cv, nil
}
