package managed

import (
	"encoding/base64"
	"fmt"
	"testing"

	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"
)

// knownHostsFixture is known_hosts fixture in the expected
// format.
var knownHostsFixture = `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
`

func TestKnownHostsCallback(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		expectedHost string
		knownHosts   []byte
		hostkey      git2go.HostkeyCertificate
		want         error
	}{
		{
			name:         "Match",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256, HashSHA256: sha256Fingerprint("nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8")},
			expectedHost: "github.com",
			want:         nil,
		},
		{
			name:         "Match with port",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256, HashSHA256: sha256Fingerprint("nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8")},
			expectedHost: "github.com:22",
			want:         nil,
		},
		{
			// Test case to specifically detect a regression introduced in v0.25.0
			// Ref: https://github.com/fluxcd/image-automation-controller/issues/378
			name:       "Match regardless of order of known_hosts",
			host:       "github.com",
			knownHosts: []byte(knownHostsFixture),
			// Use ecdsa-sha2-nistp256 instead of ssh-rsa
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256, HashSHA256: sha256Fingerprint("p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM")},
			expectedHost: "github.com:22",
			want:         nil,
		},
		{
			name:         "Hostname mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256, HashSHA256: sha256Fingerprint("nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8")},
			expectedHost: "example.com",
			want:         fmt.Errorf("host mismatch: %q %q", "example.com", "github.com"),
		},
		{
			name:         "Hostkey mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256, HashSHA256: sha256Fingerprint("ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ")},
			expectedHost: "github.com",
			want:         fmt.Errorf("hostkey could not be verified"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cert := &git2go.Certificate{Hostkey: tt.hostkey}
			callback := KnownHostsCallback(tt.expectedHost, tt.knownHosts)
			result := g.Expect(callback(cert, false, tt.host))
			if tt.want == nil {
				result.To(BeNil())
			} else {
				result.To(Equal(tt.want))
			}
		})
	}
}

func sha256Fingerprint(in string) [32]byte {
	d, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], d)
	return out
}
