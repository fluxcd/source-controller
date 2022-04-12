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

package secureloader

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"sigs.k8s.io/yaml"

	"github.com/fluxcd/source-controller/internal/helm"
)

func TestLoader(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	fakeChart := filepath.Join(tmpDir, "fake.tgz")
	g.Expect(os.WriteFile(fakeChart, []byte(""), 0o640)).To(Succeed())

	t.Run("file loader", func(t *testing.T) {
		g := NewWithT(t)

		got, err := Loader(tmpDir, fakeChart)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).To(Equal(loader.FileLoader(fakeChart)))
	})

	t.Run("dir loader", func(t *testing.T) {
		g := NewWithT(t)

		fakeChartPath := filepath.Join(tmpDir, "fake")
		g.Expect(os.Mkdir(fakeChartPath, 0o700)).To(Succeed())

		got, err := Loader(tmpDir, "fake")
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(got).To(Equal(SecureDirLoader{root: tmpDir, path: "fake", maxSize: helm.MaxChartFileSize}))
	})

	t.Run("illegal path", func(t *testing.T) {
		g := NewWithT(t)

		symlinkRoot := filepath.Join(tmpDir, "symlink")
		g.Expect(os.Mkdir(symlinkRoot, 0o700)).To(Succeed())
		symlinkPath := filepath.Join(symlinkRoot, "fake.tgz")
		g.Expect(os.Symlink(fakeChart, symlinkPath))

		got, err := Loader(symlinkRoot, symlinkPath)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err).To(BeAssignableToTypeOf(&fs.PathError{}))
		g.Expect(got).To(BeNil())
	})
}

func TestLoad(t *testing.T) {
	g := NewWithT(t)

	tmpDir := t.TempDir()
	metadata := chart.Metadata{
		Name:       "test",
		APIVersion: "v2",
		Version:    "1.0",
		Type:       "application",
	}
	b, err := yaml.Marshal(&metadata)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(os.WriteFile(filepath.Join(tmpDir, "Chart.yaml"), b, 0o640)).To(Succeed())

	got, err := Load(tmpDir, "")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).ToNot(BeNil())
	g.Expect(got.Name()).To(Equal(metadata.Name))
}
