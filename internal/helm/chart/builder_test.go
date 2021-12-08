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

package chart

import (
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
)

func TestLocalReference_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ref     LocalReference
		wantErr string
	}{
		{
			name: "ref with path",
			ref:  LocalReference{Path: "/a/path"},
		},
		{
			name: "ref with path and work dir",
			ref:  LocalReference{Path: "/a/path", WorkDir: "/with/a/workdir"},
		},
		{
			name:    "ref without path",
			ref:     LocalReference{WorkDir: "/just/a/workdir"},
			wantErr: "no path set for local chart reference",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			err := tt.ref.Validate()
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestRemoteReference_Validate(t *testing.T) {
	tests := []struct {
		name    string
		ref     RemoteReference
		wantErr string
	}{
		{
			name: "ref with name",
			ref:  RemoteReference{Name: "valid-chart-name"},
		},
		{
			name:    "ref with invalid name",
			ref:     RemoteReference{Name: "iNvAlID-ChArT-NAmE!"},
			wantErr: "invalid chart name 'iNvAlID-ChArT-NAmE!'",
		},
		{
			name:    "ref with Artifactory specific invalid format",
			ref:     RemoteReference{Name: "i-shall/not"},
			wantErr: "invalid chart name 'i-shall/not'",
		},
		{
			name:    "ref without name",
			ref:     RemoteReference{},
			wantErr: "no name set for remote chart reference",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			err := tt.ref.Validate()
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}

func TestBuildOptions_GetValuesFiles(t *testing.T) {
	tests := []struct {
		name        string
		valuesFiles []string
		want        []string
	}{
		{
			name:        "Default values.yaml",
			valuesFiles: []string{chartutil.ValuesfileName},
			want:        nil,
		},
		{
			name:        "Values files",
			valuesFiles: []string{chartutil.ValuesfileName, "foo.yaml"},
			want:        []string{chartutil.ValuesfileName, "foo.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			o := BuildOptions{ValuesFiles: tt.valuesFiles}
			g.Expect(o.GetValuesFiles()).To(Equal(tt.want))
		})
	}
}

func TestChartBuildResult_Summary(t *testing.T) {
	tests := []struct {
		name  string
		build *Build
		want  string
	}{
		{
			name: "Build with metadata",
			build: &Build{
				Name:    "chart",
				Version: "1.2.3-rc.1+bd6bf40",
			},
			want: "New 'chart' chart with version '1.2.3-rc.1+bd6bf40'",
		},
		{
			name: "Pulled chart",
			build: &Build{
				Name:    "chart",
				Version: "1.2.3-rc.1+bd6bf40",
				Path:    "chart.tgz",
			},
			want: "Pulled 'chart' chart with version '1.2.3-rc.1+bd6bf40'",
		},
		{
			name: "Packaged chart",
			build: &Build{
				Name:        "chart",
				Version:     "arbitrary-version",
				Packaged:    true,
				ValuesFiles: []string{"a.yaml", "b.yaml"},
				Path:        "chart.tgz",
			},
			want: "Packaged 'chart' chart with version 'arbitrary-version' and merged values files [a.yaml b.yaml]",
		},
		{
			name: "With values files",
			build: &Build{
				Name:        "chart",
				Version:     "arbitrary-version",
				Packaged:    true,
				ValuesFiles: []string{"a.yaml", "b.yaml"},
				Path:        "chart.tgz",
			},
			want: "Packaged 'chart' chart with version 'arbitrary-version' and merged values files [a.yaml b.yaml]",
		},
		{
			name:  "Empty build",
			build: &Build{},
			want:  "No chart build",
		},
		{
			name:  "Nil build",
			build: nil,
			want:  "No chart build",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tt.build.Summary()).To(Equal(tt.want))
		})
	}
}

func TestChartBuildResult_String(t *testing.T) {
	g := NewWithT(t)

	var result *Build
	g.Expect(result.String()).To(Equal(""))
	result = &Build{}
	g.Expect(result.String()).To(Equal(""))
	result = &Build{Path: "/foo/"}
	g.Expect(result.String()).To(Equal("/foo/"))
}

func Test_packageToPath(t *testing.T) {
	g := NewWithT(t)

	chart, err := loader.Load("../testdata/charts/helmchart-0.1.0.tgz")
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
