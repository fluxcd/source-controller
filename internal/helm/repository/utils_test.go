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

package repository

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "with slash",
			url:  "http://example.com/",
			want: "http://example.com/",
		},
		{
			name: "without slash",
			url:  "http://example.com",
			want: "http://example.com/",
		},
		{
			name: "double slash",
			url:  "http://example.com//",
			want: "http://example.com/",
		},
		{
			name: "empty",
			url:  "",
			want: "",
		},
		{
			name: "oci with slash",
			url:  "oci://example.com/",
			want: "oci://example.com",
		},
		{
			name: "oci double slash",
			url:  "oci://example.com//",
			want: "oci://example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got := NormalizeURL(tt.url)
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
