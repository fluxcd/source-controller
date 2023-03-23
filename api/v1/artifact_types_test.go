/*
Copyright 2023 The Flux authors

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

package v1

import "testing"

func TestTransformLegacyRevision(t *testing.T) {
	tests := []struct {
		rev  string
		want string
	}{
		{
			rev:  "HEAD/5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			want: "sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
		},
		{
			rev:  "main/5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			want: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
		},
		{
			rev:  "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			want: "main@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
		},
		{
			rev:  "feature/branch/5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			want: "feature/branch@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
		},
		{
			rev:  "feature/branch@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
			want: "feature/branch@sha1:5394cb7f48332b2de7c17dd8b8384bbc84b7e738",
		},
		{
			rev:  "5ac85ca617f3774baff4ae0a420b810b2546dbc9af9f346b1d55c5ed9873c55c",
			want: "sha256:5ac85ca617f3774baff4ae0a420b810b2546dbc9af9f346b1d55c5ed9873c55c",
		},
		{
			rev:  "v1.0.0",
			want: "v1.0.0",
		},
		{
			rev:  "v1.0.0-rc1",
			want: "v1.0.0-rc1",
		},
		{
			rev:  "v1.0.0-rc1+metadata",
			want: "v1.0.0-rc1+metadata",
		},
		{
			rev:  "arbitrary/revision",
			want: "arbitrary/revision",
		},
		{
			rev:  "5394cb7f48332b2de7c17dd8b8384bbc84b7xxxx",
			want: "5394cb7f48332b2de7c17dd8b8384bbc84b7xxxx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.rev, func(t *testing.T) {
			if got := TransformLegacyRevision(tt.rev); got != tt.want {
				t.Errorf("TransformLegacyRevision() = %v, want %v", got, tt.want)
			}
		})
	}
}
