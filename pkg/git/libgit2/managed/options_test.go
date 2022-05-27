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

	"github.com/fluxcd/source-controller/pkg/git"
	. "github.com/onsi/gomega"
)

func TestTransportOptions(t *testing.T) {
	tests := []struct {
		name         string
		registerOpts bool
		url          string
		opts         TransportOptions
		expectOpts   bool
		expectedOpts *TransportOptions
	}{
		{
			name:         "return registered option",
			registerOpts: true,
			url:          "https://target/?123",
			opts:         TransportOptions{},
			expectOpts:   true,
			expectedOpts: &TransportOptions{},
		},
		{
			name:         "match registered options",
			registerOpts: true,
			url:          "https://target/?876",
			opts: TransportOptions{
				TargetURL: "https://new-target/321",
				AuthOpts: &git.AuthOptions{
					CAFile: []byte{123, 213, 132},
				},
			},
			expectOpts: true,
			expectedOpts: &TransportOptions{
				TargetURL: "https://new-target/321",
				AuthOpts: &git.AuthOptions{
					CAFile: []byte{123, 213, 132},
				},
			},
		},
		{
			name:         "ignore when options not registered",
			registerOpts: false,
			url:          "",
			opts:         TransportOptions{},
			expectOpts:   false,
			expectedOpts: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			if tt.registerOpts {
				AddTransportOptions(tt.url, tt.opts)
			}

			opts, found := getTransportOptions(tt.url)
			g.Expect(found).To(Equal(found))

			if tt.expectOpts {
				g.Expect(tt.expectedOpts).To(Equal(opts))
			}

			if tt.registerOpts {
				RemoveTransportOptions(tt.url)
			}

			_, found = getTransportOptions(tt.url)
			g.Expect(found).To(BeFalse())
		})
	}
}
