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

package controllers

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

func Test_artifactSet_Diff(t *testing.T) {
	tests := []struct {
		name     string
		current  artifactSet
		updated  artifactSet
		expected bool
	}{
		{
			name: "one artifact, no diff",
			current: artifactSet{
				{
					Revision: "foo",
				},
			},
			updated: artifactSet{
				{
					Revision: "foo",
				},
			},
			expected: false,
		},
		{
			name: "one artifact, diff",
			current: artifactSet{
				{
					Revision: "foo",
				},
			},
			updated: artifactSet{
				{
					Revision: "bar",
				},
			},
			expected: true,
		},
		{
			name: "multiple artifacts, no diff",
			current: artifactSet{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			updated: artifactSet{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			expected: false,
		},
		{
			name: "multiple artifacts, diff",
			current: artifactSet{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			updated: artifactSet{
				{
					Revision: "foo",
				},
				{
					Revision: "baz",
				},
			},
			expected: true,
		},
		{
			name: "different artifact count",
			current: artifactSet{
				{
					Revision: "foo",
				},
				{
					Revision: "bar",
				},
			},
			updated: artifactSet{
				{
					Revision: "foo",
				},
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.current.Diff(tt.updated)
			if result != tt.expected {
				t.Errorf("Archive() result = %v, wantResult %v", result, tt.expected)
			}
		})
	}
}

func Test_artifactSet_Filter(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string][]byte
		want     map[string][]byte
		patterns []string
	}{
		{
			name: "empty ignore, no diff",
			input: map[string][]byte{
				"foo.yaml": nil,
			},
			want: map[string][]byte{
				"foo.yaml": nil,
			},
		},
		{
			name: "ignore starting with f",
			input: map[string][]byte{
				"foo.yaml": nil,
				"bar.yaml": nil,
			},
			want: map[string][]byte{
				"foo.yaml": nil,
			},
			patterns: []string{"f*"},
		},
		{
			name: "ignore all",
			input: map[string][]byte{
				"foo.yaml": nil,
				"bar.yaml": nil,
			},
			want: map[string][]byte{},
			patterns: []string{
				"*",
			},
		},
		{
			name: "ignore all except bar.yaml",
			input: map[string][]byte{
				"foo.yaml": nil,
				"bar.yaml": nil,
			},
			want: map[string][]byte{
				"bar.yaml": nil,
			},
			patterns: []string{
				"*",
				"!bar.yaml",
			},
		},
	}

	createFiles := func(files map[string][]byte) (dir string, err error) {
		defer func() {
			if err != nil && dir != "" {
				os.RemoveAll(dir)
			}
		}()
		dir, err = os.MkdirTemp("", "archive-test-files-")
		if err != nil {
			return
		}
		for name, b := range files {
			absPath := filepath.Join(dir, name)
			if err = os.MkdirAll(filepath.Dir(absPath), 0o750); err != nil {
				return
			}
			f, err := os.Create(absPath)
			if err != nil {
				return "", fmt.Errorf("could not create file %q: %w", absPath, err)
			}
			if n, err := f.Write(b); err != nil {
				f.Close()
				return "", fmt.Errorf("could not write %d bytes to file %q: %w", n, f.Name(), err)
			}
			f.Close()
		}
		return
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var inputSet, expectedSet artifactSet
			dir, _ := createFiles(tt.input)
			for p := range tt.input {
				inputSet = append(inputSet, &sourcev1.Artifact{Path: filepath.Join(dir, p)})
			}
			for p := range tt.want {
				expectedSet = append(expectedSet, &sourcev1.Artifact{Path: filepath.Join(dir, p)})
			}
			var ps []gitignore.Pattern
			for _, p := range tt.patterns {
				ps = append(ps, gitignore.ParsePattern(p, nil))
			}
			got, err := inputSet.Filter(ps)
			if err != nil {
				t.Errorf("Archive() error = %s", err)
			}
			if expectedSet.Diff(got) {
				t.Errorf("Archive() result = %v, wantResult %v", got, tt.want)
			}
		})
	}
}
