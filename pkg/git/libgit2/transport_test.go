/*
Copyright 2020 The Flux authors

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

package libgit2

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	git2go "github.com/libgit2/git2go/v31"
	. "github.com/onsi/gomega"
)

const (
	geoTrustRootFixture = `-----BEGIN CERTIFICATE-----
MIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG
EwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg
R2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9
9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq
fnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv
iS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU
1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+
bw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW
MPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA
ephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l
uMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn
Z57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS
tQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF
PseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un
hw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV
5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==
-----END CERTIFICATE-----`

	giag2IntermediateFixture = `-----BEGIN CERTIFICATE-----
MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT
MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i
YWwgQ0EwHhcNMTMwNDA1MTUxNTU1WhcNMTUwNDA0MTUxNTU1WjBJMQswCQYDVQQG
EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy
bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP
VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv
h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE
ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ
EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC
DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB+zCB+DAfBgNVHSMEGDAWgBTAephojYn7
qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wEgYD
VR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwOgYDVR0fBDMwMTAvoC2g
K4YpaHR0cDovL2NybC5nZW90cnVzdC5jb20vY3Jscy9ndGdsb2JhbC5jcmwwPQYI
KwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vZ3RnbG9iYWwtb2NzcC5n
ZW90cnVzdC5jb20wFwYDVR0gBBAwDjAMBgorBgEEAdZ5AgUBMA0GCSqGSIb3DQEB
BQUAA4IBAQA21waAESetKhSbOHezI6B1WLuxfoNCunLaHtiONgaX4PCVOzf9G0JY
/iLIa704XtE7JW4S615ndkZAkNoUyHgN7ZVm2o6Gb4ChulYylYbc3GrKBIxbf/a/
zG+FA1jDaFETzf3I93k9mTXwVqO94FntT0QJo544evZG0R0SnU++0ED8Vf4GXjza
HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto
WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6
yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx
-----END CERTIFICATE-----`

	googleLeafFixture = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQEBBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----`

	// googleLeafWithInvalidHashFixture is the same as googleLeafFixture, but the signature
	// algorithm in the certificate contains a nonsense OID.
	googleLeafWithInvalidHashFixture = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAWAFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQFgBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----`

	knownHostsFixture string = `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`
)

func Test_x509Callback(t *testing.T) {
	now = func() time.Time { return time.Unix(1395785200, 0) }

	tests := []struct {
		name        string
		certificate string
		host        string
		caBundle    []byte
		want        git2go.ErrorCode
	}{
		{
			name:        "Valid certificate authority bundle",
			certificate: googleLeafFixture,
			host:        "www.google.com",
			caBundle:    []byte(giag2IntermediateFixture + "\n" + geoTrustRootFixture),
			want:        git2go.ErrorCodeOK,
		},
		{
			name:        "Invalid certificate",
			certificate: googleLeafWithInvalidHashFixture,
			host:        "www.google.com",
			caBundle:    []byte(giag2IntermediateFixture + "\n" + geoTrustRootFixture),
			want:        git2go.ErrorCodeCertificate,
		},
		{
			name:        "Invalid certificate authority bundle",
			certificate: googleLeafFixture,
			host:        "www.google.com",
			caBundle:    bytes.Trim([]byte(giag2IntermediateFixture+"\n"+geoTrustRootFixture), "-"),
			want:        git2go.ErrorCodeCertificate,
		},
		{
			name:        "Missing intermediate in bundle",
			certificate: googleLeafFixture,
			host:        "www.google.com",
			caBundle:    []byte(geoTrustRootFixture),
			want:        git2go.ErrorCodeCertificate,
		},
		{
			name:        "Invalid host",
			certificate: googleLeafFixture,
			host:        "www.google.co",
			caBundle:    []byte(giag2IntermediateFixture + "\n" + geoTrustRootFixture),
			want:        git2go.ErrorCodeCertificate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cert := &git2go.Certificate{}
			if tt.certificate != "" {
				x509Cert, err := certificateFromPEM(tt.certificate)
				g.Expect(err).ToNot(HaveOccurred())
				cert.X509 = x509Cert
			}

			callback := x509Callback(tt.caBundle)
			g.Expect(callback(cert, false, tt.host)).To(Equal(tt.want))
		})
	}
}

func Test_knownHostsCallback(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		expectedHost string
		knownHosts   []byte
		hostkey      git2go.HostkeyCertificate
		want         git2go.ErrorCode
	}{
		{
			name:         "Match",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "github.com",
			want:         git2go.ErrorCodeOK,
		},
		{
			name:         "Match with port",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "github.com:22",
			want:         git2go.ErrorCodeOK,
		},
		{
			name:         "Hostname mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "example.com",
			want:         git2go.ErrorCodeUser,
		},
		{
			name:         "Hostkey mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\xb6\x03\x0e\x39\x97\x9e\xd0\xe7\x24\xce\xa3\x77\x3e\x01\x42\x09")},
			expectedHost: "github.com",
			want:         git2go.ErrorCodeCertificate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cert := &git2go.Certificate{Hostkey: tt.hostkey}
			callback := knownHostsCallback(tt.expectedHost, tt.knownHosts)
			g.Expect(callback(cert, false, tt.host)).To(Equal(tt.want))
		})
	}
}

func Test_parseKnownHosts_matches(t *testing.T) {
	tests := []struct {
		name        string
		hostkey     git2go.HostkeyCertificate
		wantMatches bool
	}{
		{"good sha256 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256 | git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA256: sha256Fingerprint("nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8")}, true},
		{"bad sha256 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256 | git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA256: sha256Fingerprint("ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ")}, false},
		{"good sha1 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")}, true},
		{"bad sha1 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("tfpLlQhDDFP3yGdewTvHNxWmAdk")}, false},
		{"good md5 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\x16\x27\xac\xa5\x76\x28\x2d\x36\x63\x1b\x56\x4d\xeb\xdf\xa6\x48")}, true},
		{"bad md5 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\xb6\x03\x0e\x39\x97\x9e\xd0\xe7\x24\xce\xa3\x77\x3e\x01\x42\x09")}, false},
		{"invalid hostkey", git2go.HostkeyCertificate{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			knownKeys, err := parseKnownHosts(knownHostsFixture)
			if err != nil {
				t.Error(err)
				return
			}
			matches := knownKeys[0].matches("github.com", tt.hostkey)
			g.Expect(matches).To(Equal(tt.wantMatches))
		})
	}
}

func Test_parseKnownHosts(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		wantErr bool
	}{
		{
			name:    "empty file",
			fixture: "",
			wantErr: false,
		},
		{
			name:    "single host",
			fixture: `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`,
			wantErr: false,
		},
		{
			name: "single host with comment",
			fixture: `# github.com
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`,
			wantErr: false,
		},
		{
			name: "multiple hosts with comments",
			fixture: `# github.com
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
# gitlab.com
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf`,
		},
		{
			name: "no host key, only comments",
			fixture: `# example.com
#github.com
# gitlab.com`,
			wantErr: false,
		},
		{
			name:    "invalid host entry",
			fixture: `github.com ssh-rsa`,
			wantErr: true,
		},
		{
			name:    "invalid content",
			fixture: `some random text`,
			wantErr: true,
		},
		{
			name: "invalid line with valid host key",
			fixture: `some random text
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := parseKnownHosts(tt.fixture)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func Test_transferProgressCallback(t *testing.T) {
	tests := []struct {
		name       string
		progress   git2go.TransferProgress
		cancelFunc func(context.CancelFunc)
		wantErr    git2go.ErrorCode
	}{
		{
			name: "ok - in progress",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 21,
			},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name: "ok - transfer complete",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 30,
			},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name: "ok - transfer complete, context cancelled",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 30,
			},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name: "error - context cancelled",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 21,
			},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    git2go.ErrorCodeUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			tpcb := transferProgressCallback(ctx)

			tt.cancelFunc(cancel)

			g.Expect(tpcb(tt.progress)).To(Equal(tt.wantErr))
		})
	}
}

func Test_transportMessageCallback(t *testing.T) {
	tests := []struct {
		name       string
		cancelFunc func(context.CancelFunc)
		wantErr    git2go.ErrorCode
	}{
		{
			name:       "ok - transport open",
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name:       "error - transport closed",
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    git2go.ErrorCodeUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			tmcb := transportMessageCallback(ctx)

			tt.cancelFunc(cancel)

			g.Expect(tmcb("")).To(Equal(tt.wantErr))
		})
	}
}

func Test_pushTransferProgressCallback(t *testing.T) {
	type pushProgress struct {
		current uint32
		total   uint32
		bytes   uint
	}
	tests := []struct {
		name       string
		progress   pushProgress
		cancelFunc func(context.CancelFunc)
		wantErr    git2go.ErrorCode
	}{
		{
			name:       "ok - in progress",
			progress:   pushProgress{current: 20, total: 25},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name:       "ok - transfer complete",
			progress:   pushProgress{current: 25, total: 25},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name:       "ok - transfer complete, context cancelled",
			progress:   pushProgress{current: 25, total: 25},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    git2go.ErrorCodeOK,
		},
		{
			name:       "error - context cancelled",
			progress:   pushProgress{current: 20, total: 25},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    git2go.ErrorCodeUser,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			ptpcb := pushTransferProgressCallback(ctx)

			tt.cancelFunc(cancel)

			g.Expect(ptpcb(tt.progress.current, tt.progress.total, tt.progress.bytes)).To(Equal(tt.wantErr))
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
