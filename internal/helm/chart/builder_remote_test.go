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
	"testing"

	. "github.com/onsi/gomega"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chartutil"
)

func Test_mergeChartValues(t *testing.T) {
	tests := []struct {
		name    string
		chart   *helmchart.Chart
		paths   []string
		want    map[string]interface{}
		wantErr string
	}{
		{
			name: "merges values",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "a.yaml", Data: []byte("a: b")},
					{Name: "b.yaml", Data: []byte("b: c")},
					{Name: "c.yaml", Data: []byte("b: d")},
				},
			},
			paths: []string{"a.yaml", "b.yaml", "c.yaml"},
			want: map[string]interface{}{
				"a": "b",
				"b": "d",
			},
		},
		{
			name: "uses chart values",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "c.yaml", Data: []byte("b: d")},
				},
				Values: map[string]interface{}{
					"a": "b",
				},
			},
			paths: []string{chartutil.ValuesfileName, "c.yaml"},
			want: map[string]interface{}{
				"a": "b",
				"b": "d",
			},
		},
		{
			name: "unmarshal error",
			chart: &helmchart.Chart{
				Files: []*helmchart.File{
					{Name: "invalid", Data: []byte("abcd")},
				},
			},
			paths:   []string{"invalid"},
			wantErr: "unmarshaling values from 'invalid' failed",
		},
		{
			name:    "error on invalid path",
			chart:   &helmchart.Chart{},
			paths:   []string{"a.yaml"},
			wantErr: "no values file found at path 'a.yaml'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := mergeChartValues(tt.chart, tt.paths)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func Test_pathIsDir(t *testing.T) {
	tests := []struct {
		name string
		p    string
		want bool
	}{
		{name: "directory", p: "../testdata/", want: true},
		{name: "file", p: "../testdata/local-index.yaml", want: false},
		{name: "not found error", p: "../testdata/does-not-exist.yaml", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(pathIsDir(tt.p)).To(Equal(tt.want))
		})
	}
}
