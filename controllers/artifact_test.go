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
	"testing"
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
