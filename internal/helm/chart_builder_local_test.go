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
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"
	helmchart "helm.sh/helm/v3/pkg/chart"
)

func Test_mergeFileValues(t *testing.T) {
	tests := []struct {
		name    string
		files   []*helmchart.File
		paths   []string
		want    map[string]interface{}
		wantErr string
	}{
		{
			name: "merges values from files",
			files: []*helmchart.File{
				{Name: "a.yaml", Data: []byte("a: b")},
				{Name: "b.yaml", Data: []byte("b: c")},
				{Name: "c.yaml", Data: []byte("b: d")},
			},
			paths: []string{"a.yaml", "b.yaml", "c.yaml"},
			want: map[string]interface{}{
				"a": "b",
				"b": "d",
			},
		},
		{
			name:    "illegal traverse",
			paths:   []string{"../../../traversing/illegally/a/p/a/b"},
			wantErr: "no values file found at path '/traversing/illegally/a/p/a/b'",
		},
		{
			name: "unmarshal error",
			files: []*helmchart.File{
				{Name: "invalid", Data: []byte("abcd")},
			},
			paths:   []string{"invalid"},
			wantErr: "unmarshaling values from 'invalid' failed",
		},
		{
			name:    "error on invalid path",
			paths:   []string{"a.yaml"},
			wantErr: "no values file found at path '/a.yaml'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			baseDir, err := os.MkdirTemp("", "merge-file-values-*")
			g.Expect(err).ToNot(HaveOccurred())
			defer os.RemoveAll(baseDir)

			for _, f := range tt.files {
				g.Expect(os.WriteFile(filepath.Join(baseDir, f.Name), f.Data, 0644)).To(Succeed())
			}

			got, err := mergeFileValues(baseDir, tt.paths)
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

func Test_copyFileToPath(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{
			name: "copies input file",
			in:   "testdata/local-index.yaml",
		},
		{
			name:    "invalid input file",
			in:      "testdata/invalid.tgz",
			wantErr: "failed to open file to copy from",
		},
		{
			name:    "invalid input directory",
			in:      "testdata/charts",
			wantErr: "failed to read from source during copy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			out := tmpFile("copy-0.1.0", ".tgz")
			defer os.RemoveAll(out)
			err := copyFileToPath(tt.in, out)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(out).To(BeARegularFile())
			f1, err := os.ReadFile(tt.in)
			g.Expect(err).ToNot(HaveOccurred())
			f2, err := os.ReadFile(out)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(f2).To(Equal(f1))
		})
	}
}
