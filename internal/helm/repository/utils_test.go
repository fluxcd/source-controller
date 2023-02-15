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
		name    string
		url     string
		want    string
		wantErr bool
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
			name: "oci with slash",
			url:  "oci://example.com/",
			want: "oci://example.com",
		},
		{
			name: "oci double slash",
			url:  "oci://example.com//",
			want: "oci://example.com",
		},
		{
			name: "url with query",
			url:  "http://example.com?st=pr",
			want: "http://example.com/?st=pr",
		},
		{
			name: "url with slash and query",
			url:  "http://example.com/?st=pr",
			want: "http://example.com/?st=pr",
		},
		{
			name: "empty url",
			url:  "",
			want: "",
		},
		{
			name:    "bad url",
			url:     "://badurl.",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := NormalizeURL(tt.url)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}

			g.Expect(err).To(Not(HaveOccurred()))
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
