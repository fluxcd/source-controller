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

package oci

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v2/pkg/cosign"
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
			PublicKey: []byte("foo"),
			ROpt:      nil,
		},
	}, {
		name: "keychain option",
		opts: []Options{WithRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain))},
		want: &options{
			PublicKey: nil,
			ROpt:      []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)},
		},
	}, {
		name: "keychain and authenticator option",
		opts: []Options{WithRemoteOptions(
			remote.WithAuth(&authn.Basic{Username: "foo", Password: "bar"}),
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
		)},
		want: &options{
			PublicKey: nil,
			ROpt: []remote.Option{
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
			PublicKey: nil,
			ROpt: []remote.Option{
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
			Identities: []cosign.Identity{
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
			if !reflect.DeepEqual(o.PublicKey, test.want.PublicKey) {
				t.Errorf("got %#v, want %#v", &o.PublicKey, test.want.PublicKey)
			}

			if test.want.ROpt != nil {
				if len(o.ROpt) != len(test.want.ROpt) {
					t.Errorf("got %d remote options, want %d", len(o.ROpt), len(test.want.ROpt))
				}
				return
			}

			if test.want.ROpt == nil {
				if len(o.ROpt) != 0 {
					t.Errorf("got %d remote options, want %d", len(o.ROpt), 0)
				}
			}
		})
	}
}
