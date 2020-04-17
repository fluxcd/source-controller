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
