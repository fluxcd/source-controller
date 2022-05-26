package managed

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"
)

// knownHostsFixture is known_hosts fixture in the expected
// format.
var knownHostsFixture = `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`

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
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "github.com",
			want:         nil,
		},
		{
			name:         "Match with port",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "github.com:22",
			want:         nil,
		},
		{
			name:         "Hostname mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "example.com",
			want:         fmt.Errorf("host mismatch: %q %q", "example.com", "github.com"),
		},
		{
			name:         "Hostkey mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\xb6\x03\x0e\x39\x97\x9e\xd0\xe7\x24\xce\xa3\x77\x3e\x01\x42\x09")},
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
func md5Fingerprint(in string) [16]byte {
	var out [16]byte
	copy(out[:], in)
	return out
}

func sha1Fingerprint(in string) [20]byte {
	d, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	var out [20]byte
	copy(out[:], d)
	return out
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

func certificateFromPEM(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
