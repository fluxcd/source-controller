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
)

func TestCacheKey(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddress1 string
		user1          string
		passphrase1    string
		pubKey1        []byte
		remoteAddress2 string
		user2          string
		passphrase2    string
		pubKey2        []byte
		expectMatch    bool
	}{
		{
			name:           "same remote addresses with no config",
			remoteAddress1: "1.1.1.1",
			remoteAddress2: "1.1.1.1",
			expectMatch:    true,
		},
		{
			name:           "same remote addresses with different config",
			remoteAddress1: "1.1.1.1",
			user1:          "joe",
			remoteAddress2: "1.1.1.1",
			user2:          "another-joe",
			expectMatch:    false,
		},
		{
			name:           "different remote addresses with no config",
			remoteAddress1: "8.8.8.8",
			remoteAddress2: "1.1.1.1",
			expectMatch:    false,
		},
		{
			name:           "different remote addresses with same config",
			remoteAddress1: "8.8.8.8",
			user1:          "legit",
			remoteAddress2: "1.1.1.1",
			user2:          "legit",
			expectMatch:    false,
		},
		{
			name:           "same remote addresses with same pubkey signers",
			remoteAddress1: "1.1.1.1",
			user1:          "same-jane",
			pubKey1:        []byte{255, 123, 0},
			remoteAddress2: "1.1.1.1",
			user2:          "same-jane",
			pubKey2:        []byte{255, 123, 0},
			expectMatch:    true,
		},
		{
			name:           "same remote addresses with different pubkey signers",
			remoteAddress1: "1.1.1.1",
			user1:          "same-jane",
			pubKey1:        []byte{255, 123, 0},
			remoteAddress2: "1.1.1.1",
			user2:          "same-jane",
			pubKey2:        []byte{0, 123, 0},
			expectMatch:    false,
		},
		{
			name:           "same remote addresses with pubkey signers and passphrases",
			remoteAddress1: "1.1.1.1",
			user1:          "same-jane",
			passphrase1:    "same-pass",
			pubKey1:        []byte{255, 123, 0},
			remoteAddress2: "1.1.1.1",
			user2:          "same-jane",
			passphrase2:    "same-pass",
			pubKey2:        []byte{255, 123, 0},
			expectMatch:    true,
		},
		{
			name:           "same remote addresses with pubkey signers and different passphrases",
			remoteAddress1: "1.1.1.1",
			user1:          "same-jane",
			passphrase1:    "same-pass",
			pubKey1:        []byte{255, 123, 0},
			remoteAddress2: "1.1.1.1",
			user2:          "same-jane",
			passphrase2:    "different-pass",
			pubKey2:        []byte{255, 123, 0},
			expectMatch:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheKey1 := cacheKey(tt.remoteAddress1, tt.user1, tt.passphrase1, tt.pubKey1)
			cacheKey2 := cacheKey(tt.remoteAddress2, tt.user2, tt.passphrase2, tt.pubKey2)

			if tt.expectMatch && cacheKey1 != cacheKey2 {
				t.Errorf("cache keys '%s' and '%s' should match", cacheKey1, cacheKey2)
			}

			if !tt.expectMatch && cacheKey1 == cacheKey2 {
				t.Errorf("cache keys '%s' and '%s' should not match", cacheKey1, cacheKey2)
			}
		})
	}
}
