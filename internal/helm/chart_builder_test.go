/*
Copyright 2021 The Flux authors

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
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart/loader"
)

func TestChartBuildResult_String(t *testing.T) {
	g := NewWithT(t)

	var result *ChartBuild
	g.Expect(result.String()).To(Equal(""))
	result = &ChartBuild{}
	g.Expect(result.String()).To(Equal(""))
	result = &ChartBuild{Path: "/foo/"}
	g.Expect(result.String()).To(Equal("/foo/"))
}

func Test_packageToPath(t *testing.T) {
	g := NewWithT(t)

	chart, err := loader.Load("testdata/charts/helmchart-0.1.0.tgz")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(chart).ToNot(BeNil())

	out := tmpFile("chart-0.1.0", ".tgz")
	defer os.RemoveAll(out)
	err = packageToPath(chart, out)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(out).To(BeARegularFile())
	_, err = loader.Load(out)
	g.Expect(err).ToNot(HaveOccurred())
}

func tmpFile(prefix, suffix string) string {
	randBytes := make([]byte, 16)
	rand.Read(randBytes)
	return filepath.Join(os.TempDir(), prefix+hex.EncodeToString(randBytes)+suffix)
}
