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
	"github.com/sigstore/cosign/v2/pkg/cosign"

	testproxy "github.com/werf/nelm-source-controller/tests/proxy"
	testregistry "github.com/werf/nelm-source-controller/tests/registry"
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx := context.Background()

			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = http.ProxyURL(tt.proxyURL)

			var opts []Options
			opts = append(opts, WithRemoteOptions(remote.WithTransport(transport)))
			opts = append(opts, WithPublicKey(keys.PublicBytes))

			verifier, err := NewCosignVerifier(ctx, opts...)
			g.Expect(err).NotTo(HaveOccurred())

			_, err = verifier.Verify(ctx, ref)
			g.Expect(err.Error()).To(ContainSubstring(tt.err))
		})
	}
}
