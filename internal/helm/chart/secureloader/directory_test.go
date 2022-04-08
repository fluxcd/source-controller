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
	"testing"

	. "github.com/onsi/gomega"
)

func Test_isSecureSymlinkPath(t *testing.T) {
	tests := []struct {
		name    string
		root    string
		absPath string
		safe    bool
		wantErr string
	}{
		{
			name:    "absolute path in root",
			root:    "/",
			absPath: "/bar/",
			safe:    true,
		},

		{
			name:    "abs path not relative to root",
			root:    "/working/dir",
			absPath: "/working/in/another/dir",
			safe:    false,
			wantErr: "symlink traverses outside root boundary",
		},
		{
			name:    "abs path relative to root",
			root:    "/working/dir/",
			absPath: "/working/dir/path",
			safe:    true,
		},
		{
			name:    "illegal abs path",
			root:    "/working/dir",
			absPath: "/working/dir/../but/not/really",
			safe:    false,
			wantErr: "symlink traverses outside root boundary",
		},
		{
			name:    "illegal root",
			root:    "working/dir/",
			absPath: "/working/dir",
			safe:    false,
			wantErr: "cannot calculate path relative to root for resolved symlink",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := isSecureSymlinkPath(tt.root, tt.absPath)
			g.Expect(got).To(Equal(tt.safe))
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
		})
	}
}
