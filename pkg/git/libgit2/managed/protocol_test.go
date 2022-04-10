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
			name:        "azure devops via SSH is not upgraded to ssh+managed when feature enabled",
			in:          "ssh://git@ssh.dev.azure.com:22/v3/org-name/project-name/repo-name",
			expected:    "ssh://git@ssh.dev.azure.com:22/v3/org-name/project-name/repo-name",
			autoUpgrade: true,
		},
		{
			name:        "azure devops via SSH is not upgraded to ssh+managed when feature disabled",
			in:          "ssh://git@ssh.dev.azure.com:22/v3/org-name/project-name/repo-name",
			expected:    "ssh://git@ssh.dev.azure.com:22/v3/org-name/project-name/repo-name",
			autoUpgrade: false,
		},
		{
			name:     "ssh+unmanaged is changed to ssh when autoUpgrade enabled",
			in:       "ssh+unmanaged://git@server:22/repo-path",
			expected: "ssh://git@server:22/repo-path",
		},
		{
			name:        "auto upgrade to ssh+managed when feature enabled",
			in:          "ssh://git@github.com:22/user-name/repo-name",
			expected:    "ssh+managed://git@github.com:22/user-name/repo-name",
			autoUpgrade: true,
		},
		{
			name:     "do not auto upgrade when feature is disabled",
			in:       "ssh://git@github.com:22/user-name/repo-name",
			expected: "ssh://git@github.com:22/user-name/repo-name",
		},
		{
			name:        "ssh+managed is ignored when feature is enabled",
			in:          "ssh+managed://git@server:22/repo-path",
			expected:    "ssh+managed://git@server:22/repo-path",
			autoUpgrade: true,
		},
		{
			name:     "ssh+managed is ignored when feature is disabled",
			in:       "ssh+managed://git@server:22/repo-path",
			expected: "ssh+managed://git@server:22/repo-path",
		},
		{
			name:        "ssh+git is ignored",
			in:          "ssh+git://git@server:22/repo-path",
			expected:    "ssh+git://git@server:22/repo-path",
			autoUpgrade: true,
		},
		{
			name:        "git+ssh is ignored",
			in:          "git+ssh://git@server:22/repo-path",
			expected:    "git+ssh://git@server:22/repo-path",
			autoUpgrade: true,
		},
		{
			name:        "azure devops via HTTPS is upgraded to https+managed when feature enabled",
			in:          "https://flexfloxflux@dev.azure.com/flexfloxflux/flux-testing/_git/flux-testing",
			expected:    "https+managed://flexfloxflux@dev.azure.com/flexfloxflux/flux-testing/_git/flux-testing",
			autoUpgrade: true,
		},
		{
			name:        "azure devops via HTTP is not upgraded to https+managed when feature disabled",
			in:          "https://flexfloxflux@dev.azure.com/flexfloxflux/flux-testing/_git/flux-testing",
			expected:    "https://flexfloxflux@dev.azure.com/flexfloxflux/flux-testing/_git/flux-testing",
			autoUpgrade: false,
		},
		{
			name:     "HTTP is ignored when feature disabled",
			in:       "http://server/repo-path",
			expected: "http://server/repo-path",
		},
		{
			name:        "HTTP is upgraded when feature enabled",
			in:          "http://server/repo-path",
			expected:    "http+managed://server/repo-path",
			autoUpgrade: true,
		},
		{
			name:     "HTTPS is ignored when feature disabled",
			in:       "https://server/repo-path",
			expected: "https://server/repo-path",
		},
		{
			name:        "HTTPS is upgraded when feature enabled",
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
