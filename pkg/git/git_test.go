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

package git

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

const (
	encodedCommitFixture = `tree f0c522d8cc4c90b73e2bc719305a896e7e3c108a
parent eb167bc68d0a11530923b1f24b4978535d10b879
author Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300
committer Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300

Update containerd and runc to fix CVEs

Signed-off-by: Stefan Prodan <stefan.prodan@gmail.com>
`

	malformedEncodedCommitFixture = `parent eb167bc68d0a11530923b1f24b4978535d10b879
author Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300
committer Stefan Prodan <stefan.prodan@gmail.com> 1633681364 +0300

Update containerd and runc to fix CVEs

Signed-off-by: Stefan Prodan <stefan.prodan@gmail.com>
`

	signatureCommitFixture = `-----BEGIN PGP SIGNATURE-----

iHUEABEIAB0WIQQHgExUr4FrLdKzpNYyma6w5AhbrwUCYV//1AAKCRAyma6w5Ahb
r7nJAQCQU4zEJu04/Q0ac/UaL6htjhq/wTDNMeUM+aWG/LcBogEAqFUea1oR2BJQ
JCJmEtERFh39zNWSazQmxPAFhEE0kbc=
=+Wlj
-----END PGP SIGNATURE-----`

	armoredKeyRingFixture = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=/4e+
-----END PGP PUBLIC KEY BLOCK-----
`

	keyRingFingerprintFixture = "3299AEB0E4085BAF"

	malformedKeyRingFixture = `
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQSuBF9+HgMRDADKT8UBcSzpTi4JXt/ohhVW3x81AGFPrQvs6MYrcnNJfIkPTJD8
mY5T7j1fkaN5wcf1wnxM9qTcW8BodkWNGEoEYOtVuigLSxPFqIncxK0PHvdU8ths
TEInBrgZv9t6xIVa4QngOEUd2D/aYni7M+75z7ntgj6eU1xLZ60upRFn05862OvJ
rZFUvzjsZXMAO3enCu2VhG/2axCY/5uI8PgWjyiKV2TH4LBJgzlb0v6SyI+fYf5K
Bg2WzDuLKvQBi9tFSwnUbQoFFlOeiGW8G/bdkoJDWeS1oYgSD3nkmvXvrVESCrbT
-----END PGP PUBLIC KEY BLOCK-----
`
)

func TestCommit_String(t *testing.T) {
	tests := []struct {
		name   string
		commit *Commit
		want   string
	}{
		{
			name: "Reference and commit",
			commit: &Commit{
				Hash:      []byte("commit"),
				Reference: "refs/heads/main",
			},
			want: "main/commit",
		},
		{
			name: "Reference with slash and commit",
			commit: &Commit{
				Hash:      []byte("commit"),
				Reference: "refs/heads/feature/branch",
			},
			want: "feature/branch/commit",
		},
		{
			name: "No reference",
			commit: &Commit{
				Hash: []byte("commit"),
			},
			want: "HEAD/commit",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tt.commit.String()).To(Equal(tt.want))
		})
	}
}

func TestCommit_Verify(t *testing.T) {
	tests := []struct {
		name     string
		commit   *Commit
		keyRings []string
		want     string
		wantErr  string
	}{
		{
			name: "Valid commit signature",
			commit: &Commit{
				Encoded:   []byte(encodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			keyRings: []string{armoredKeyRingFixture},
			want:     keyRingFingerprintFixture,
		},
		{
			name: "Malformed encoded commit",
			commit: &Commit{
				Encoded:   []byte(malformedEncodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			keyRings: []string{armoredKeyRingFixture},
			wantErr:  "failed to verify commit with any of the given key rings",
		},
		{
			name: "Malformed key ring",
			commit: &Commit{
				Encoded:   []byte(encodedCommitFixture),
				Signature: signatureCommitFixture,
			},
			keyRings: []string{malformedKeyRingFixture},
			wantErr:  "failed to read armored key ring: unexpected EOF",
		},
		{
			name: "Missing signature",
			commit: &Commit{
				Encoded: []byte(encodedCommitFixture),
			},
			keyRings: []string{armoredKeyRingFixture},
			wantErr:  "commit does not have a PGP signature",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tt.commit.Verify(tt.keyRings...)
			if tt.wantErr != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeEmpty())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestCommit_ShortMessage(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "short message",
			input: "a short commit message",
			want:  "a short commit message",
		},
		{
			name:  "long message",
			input: "hello world - a long commit message for testing long messages",
			want:  "hello world - a long commit message for testing lo...",
		},
		{
			name: "multi line commit message",
			input: `title of the commit

detailed description
of the commit`,
			want: "title of the commit",
		},
		{
			name:  "message with unicodes",
			input: "a message with unicode characters 你好世界 🏞️ 🏕️ ⛩️ 🌌",
			want:  "a message with unicode characters 你好世界 🏞️ 🏕️ ⛩️ 🌌",
		},
		{
			name:  "empty commit message",
			input: "",
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			c := Commit{Message: tt.input}
			g.Expect(c.ShortMessage()).To(Equal(tt.want))
		})
	}
}

func TestIsConcreteCommit(t *testing.T) {
	tests := []struct {
		name   string
		commit Commit
		result bool
	}{
		{
			name: "concrete commit",
			commit: Commit{
				Hash:      Hash("foo"),
				Reference: "refs/tags/main",
				Author: Signature{
					Name: "user", Email: "user@example.com", When: time.Now(),
				},
				Committer: Signature{
					Name: "user", Email: "user@example.com", When: time.Now(),
				},
				Signature: "signature",
				Encoded:   []byte("commit-content"),
				Message:   "commit-message",
			},
			result: true,
		},
		{
			name:   "partial commit",
			commit: Commit{Hash: Hash("foo")},
			result: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(IsConcreteCommit(tt.commit)).To(Equal(tt.result))
		})
	}
}
