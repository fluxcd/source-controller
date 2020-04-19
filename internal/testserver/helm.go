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

package testserver

import (
	"io/ioutil"
	"path/filepath"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/repo"
	"sigs.k8s.io/yaml"
)

func NewTempHelmServer() (*Helm, error) {
	server, err := NewTempHTTPServer()
	if err != nil {
		return nil, err
	}
	helm := &Helm{server}
	return helm, nil
}

type Helm struct {
	*HTTP
}

func (s *Helm) GenerateIndex() error {
	index, err := repo.IndexDirectory(s.HTTP.docroot, s.HTTP.URL())
	if err != nil {
		return err
	}
	d, err := yaml.Marshal(index)
	if err != nil {
		return err
	}
	f := filepath.Join(s.HTTP.docroot, "index.yaml")
	return ioutil.WriteFile(f, d, 0644)
}

func (s *Helm) PackageChart(path string) error {
	return s.PackageChartWithVersion(path, "")
}

func (s *Helm) PackageChartWithVersion(path, version string) error {
	pkg := action.NewPackage()
	pkg.Destination = s.HTTP.docroot
	pkg.Version = version
	_, err := pkg.Run(path, nil)
	return err
}
