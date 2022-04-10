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

package managed

import (
	"testing"

	. "github.com/onsi/gomega"
)

func Test_EnsureProtocol(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name        string
		in          string
		expected    string
		autoUpgrade bool
	}{
		{
			name:     "ssh+unmanaged is changed to ssh if autoUpgrade enabled",
			in:       "ssh+unmanaged://git@server:22/repo-path",
			expected: "ssh://git@server:22/repo-path",
		},
		{
			name:        "auto upgrade to ssh+managed if feature enabled",
			in:          "ssh://git@github.com:22/user-name/repo-name",
			expected:    "ssh+managed://git@github.com:22/user-name/repo-name",
			autoUpgrade: true,
		},
		{
			name:     "do not auto upgrade if feature is disabled",
			in:       "ssh://git@github.com:22/user-name/repo-name",
			expected: "ssh://git@github.com:22/user-name/repo-name",
		},
		{
			name:     "ssh+managed is ignored",
			in:       "ssh+managed://git@server:22/repo-path",
			expected: "ssh+managed://git@server:22/repo-path",
		},
		{
			name:     "ssh+git is ignored",
			in:       "ssh+git://git@server:22/repo-path",
			expected: "ssh+git://git@server:22/repo-path",
		},
		{
			name:     "git+ssh is ignored",
			in:       "git+ssh://git@server:22/repo-path",
			expected: "git+ssh://git@server:22/repo-path",
		},
		{
			name:     "HTTP is ignored if feature disabled",
			in:       "http://server/repo-path",
			expected: "http://server/repo-path",
		},
		{
			name:        "HTTP is upgraded if feature enabled",
			in:          "http://server/repo-path",
			expected:    "http+managed://server/repo-path",
			autoUpgrade: true,
		},
		{
			name:     "HTTPS is ignored if feature disabled",
			in:       "https://server/repo-path",
			expected: "https://server/repo-path",
		},
		{
			name:        "HTTPS is upgraded if feature enabled",
			in:          "https://server/repo-path",
			expected:    "https+managed://server/repo-path",
			autoUpgrade: true,
		},
		{
			name:     "empty string is ignored",
			in:       "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			autoUpgradeEnabled = tt.autoUpgrade

			actual := EnsureProtocol(tt.in)
			g.Expect(actual).To(Equal(tt.expected))
		})
	}
}
