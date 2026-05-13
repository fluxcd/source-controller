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

package cosign

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/gomega"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/root"

	testproxy "github.com/fluxcd/source-controller/tests/proxy"
	testregistry "github.com/fluxcd/source-controller/tests/registry"
)

func TestOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []Options
		want *options
	}{{
		name: "no options",
		want: &options{},
	}, {
		name: "trusted root option",
		opts: []Options{WithTrustedRoot([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`))},
		want: &options{
			trustedRoot: []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`),
		},
	}, {
		name: "signature option",
		opts: []Options{WithPublicKey([]byte("foo"))},
		want: &options{
			publicKey: []byte("foo"),
			rOpt:      nil,
		},
	}, {
		name: "keychain option",
		opts: []Options{WithRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain))},
		want: &options{
			publicKey: nil,
			rOpt:      []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
		},
	}, {
		name: "keychain and authenticator option",
		opts: []Options{WithRemoteOptions(
			remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		)},
		want: &options{
			publicKey: nil,
			rOpt: []remote.Option{
				remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				remote.WithAuthFromKeychain(authn.DefaultKeychain),
			},
		},
	}, {
		name: "keychain, authenticator and transport option",
		opts: []Options{WithRemoteOptions(
			remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithTransport(http.DefaultTransport),
		)},
		want: &options{
			publicKey: nil,
			rOpt: []remote.Option{
				remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
				remote.WithAuthFromKeychain(authn.DefaultKeychain),
				remote.WithTransport(http.DefaultTransport),
			},
		},
	}, {
		name: "identities option",
		opts: []Options{WithIdentities([]cosign.Identity{
			{
				SubjectRegExp: "test-user",
				IssuerRegExp:  "^https://token.actions.githubusercontent.com$",
			},
			{
				SubjectRegExp: "dev-user",
				IssuerRegExp:  "^https://accounts.google.com$",
			},
		})},
		want: &options{
			identities: []cosign.Identity{
				{
					SubjectRegExp: "test-user",
					IssuerRegExp:  "^https://token.actions.githubusercontent.com$",
				},
				{
					SubjectRegExp: "dev-user",
					IssuerRegExp:  "^https://accounts.google.com$",
				},
			},
		},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := options{}
			for _, opt := range test.opts {
				opt(&o)
			}
			if !reflect.DeepEqual(o.publicKey, test.want.publicKey) {
				t.Errorf("got %#v, want %#v", &o.publicKey, test.want.publicKey)
			}

			if !reflect.DeepEqual(o.trustedRoot, test.want.trustedRoot) {
				t.Errorf("got trustedRoot %#v, want %#v", o.trustedRoot, test.want.trustedRoot)
			}

			if test.want.rOpt != nil {
				if len(o.rOpt) != len(test.want.rOpt) {
					t.Errorf("got %d remote options, want %d", len(o.rOpt), len(test.want.rOpt))
				}
				return
			}

			if test.want.rOpt == nil {
				if len(o.rOpt) != 0 {
					t.Errorf("got %d remote options, want %d", len(o.rOpt), 0)
				}
			}
		})
	}
}

func TestRekorURLFromTrustedRoot(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantURL string
		wantErr string
	}{
		{
			name:    "extracts base URL from tlog entry",
			json:    trustedRootJSON("https://rekor.example.com"),
			wantURL: "https://rekor.example.com",
		},
		{
			name:    "error when no tlogs",
			json:    `{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","tlogs":[]}`,
			wantErr: "no transparency log entries found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tr, err := root.NewTrustedRootFromJSON([]byte(tt.json))
			if tt.wantErr != "" {
				// If parsing succeeds with no tlogs, check rekorURLFromTrustedRoot.
				if err == nil {
					_, err = rekorURLFromTrustedRoot(tr)
					g.Expect(err).To(HaveOccurred())
					g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				}
				return
			}
			g.Expect(err).NotTo(HaveOccurred())

			gotURL, err := rekorURLFromTrustedRoot(tr)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(gotURL).To(Equal(tt.wantURL))
		})
	}
}

func TestNewCosignVerifierWithTrustedRoot(t *testing.T) {
	g := NewWithT(t)

	ctx := context.Background()
	vf := NewCosignVerifierFactory()

	t.Run("keyless with custom trusted root", func(t *testing.T) {
		trJSON := trustedRootJSON("https://rekor.custom.example.com")

		verifier, err := vf.NewCosignVerifier(ctx,
			WithTrustedRoot([]byte(trJSON)),
			WithIdentities([]cosign.Identity{
				{
					SubjectRegExp: ".*",
					IssuerRegExp:  ".*",
				},
			}),
		)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(verifier).NotTo(BeNil())
		g.Expect(verifier.opts.TrustedMaterial).NotTo(BeNil())
		g.Expect(verifier.opts.RekorClient).NotTo(BeNil())
	})

	t.Run("invalid trusted root JSON", func(t *testing.T) {
		_, err := vf.NewCosignVerifier(ctx,
			WithTrustedRoot([]byte("not-valid-json")),
		)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("unable to parse trusted root"))
	})
}

// trustedRootJSON returns a minimal valid trusted_root.json with the given
// Rekor base URL. The ECDSA P-256 public key is a test key.
func trustedRootJSON(rekorURL string) string {
	return fmt.Sprintf(`{
  "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "tlogs": [
    {
      "baseUrl": "%s",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {
          "start": "2021-01-12T11:53:27.000Z"
        }
      },
      "logId": {
        "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
      }
    }
  ],
  "certificateAuthorities": [
    {
      "subject": {
        "organization": "test",
        "commonName": "test"
      },
      "uri": "https://fulcio.example.com",
      "certChain": {
        "certificates": [
          {
            "rawBytes": "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="
          }
        ]
      },
      "validFor": {
        "start": "2021-03-07T03:20:29.000Z",
        "end": "2099-12-31T23:59:59.999Z"
      }
    }
  ],
  "ctlogs": [
    {
      "baseUrl": "https://ctfe.example.com",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {
          "start": "2021-01-12T11:53:27.000Z"
        }
      },
      "logId": {
        "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
      }
    }
  ]
}`, rekorURL)
}

func TestPrivateKeyVerificationWithProxy(t *testing.T) {
	g := NewWithT(t)

	registryAddr := testregistry.New(t)

	tagURL := fmt.Sprintf("%s/fluxcd/source-controller:v1.3.0", registryAddr)
	ref, err := name.ParseReference(tagURL)
	g.Expect(err).NotTo(HaveOccurred())

	proxyAddr, proxyPort := testproxy.New(t)

	keys, err := cosign.GenerateKeyPair(func(b bool) ([]byte, error) {
		return []byte("cosign-password"), nil
	})
	g.Expect(err).NotTo(HaveOccurred())

	tests := []struct {
		name     string
		proxyURL *url.URL
		err      string
	}{
		{
			name:     "with correct proxy",
			proxyURL: &url.URL{Scheme: "http", Host: proxyAddr},
			err:      "image tag not found",
		},
		{
			name:     "with incorrect proxy",
			proxyURL: &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", proxyPort+1)},
			err:      "connection refused",
		},
	}

	vf := NewCosignVerifierFactory()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx := context.Background()

			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(tt.proxyURL)

			var opts []Options
			opts = append(opts, WithRemoteOptions(remote.WithTransport(transport)))
			opts = append(opts, WithPublicKey(keys.PublicBytes))

			verifier, err := vf.NewCosignVerifier(ctx, opts...)
			g.Expect(err).NotTo(HaveOccurred())

			_, err = verifier.Verify(ctx, ref)
			g.Expect(err.Error()).To(ContainSubstring(tt.err))
		})
	}
}
