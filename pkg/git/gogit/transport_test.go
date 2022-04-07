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

package gogit

import (
	"errors"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	. "github.com/onsi/gomega"

	"github.com/fluxcd/source-controller/pkg/git"
)

const (
	// privateKeyFixture is a randomly generated password less
	// 512bit RSA private key.
	privateKeyFixture = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCrakELAKxozvwJijQEggYlTvS1QTZx1DaBwOhW/4kRSuR21plu
xuQeyuUiztoWeb9jgW7wjzG4j1PIJjdbsgjPIcIZ4PBY7JeEW+QRopfwuN8MHXNp
uTLgIHbkmhoOg5qBEcjzO/lEOOPpV0EmbObgqv3+wRmLJrgfzWl/cTtRewIDAQAB
AoGAawKFImpEN5Xn78iwWpQVZBsbV0AjzgHuGSiloxIZrorzf2DPHkHZzYNaclVx
/o/4tBTsfg7WumH3qr541qyZJDgU7iRMABwmx0v1vm2wQiX7NJzLzH2E9vlMC3mw
d8S99g9EqRuNH98XX8su34B9WGRPqiKvEm0RW8Hideo2/KkCQQDbs6rHcriKQyPB
paidHZAfguu0eVbyHT2EgLgRboWE+tEAqFEW2ycqNL3VPz9fRvwexbB6rpOcPpQJ
DEL4XB2XAkEAx7xJz8YlCQ2H38xggK8R8EUXF9Zhb0fqMJHMNmao1HCHVMtbsa8I
jR2EGyQ4CaIqNG5tdWukXQSJrPYDRWNvvQJAZX3rP7XUYDLB2twvN12HzbbKMhX3
v2MYnxRjc9INpi/Dyzz2MMvOnOW+aDuOh/If2AtVCmeJUx1pf4CFk3viQwJBAKyC
t824+evjv+NQBlme3AOF6PgxtV4D4wWoJ5Uk/dTejER0j/Hbl6sqPxuiILRRV9qJ
Ngkgu4mLjc3RfenEhJECQAx8zjWUE6kHHPGAd9DfiAIQ4bChqnyS0Nwb9+Gd4hSE
P0Ah10mHiK/M0o3T8Eanwum0gbQHPnOwqZgsPkwXRqQ=
-----END RSA PRIVATE KEY-----`

	// privateKeyPassphraseFixture is a randomly generated
	// 512bit RSA private key with password foobar.
	privateKeyPassphraseFixture = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,0B016973B2A761D31E6B388D0F327C35

X9GET/qAyZkAJBl/RK+1XX75NxONgdUfZDw7PIYi/g+Efh3Z5zH5kh/dx9lxH5ZG
HGCqPAeMO/ofGDGtDULWW6iqDUFRu5gPgEVSCnnbqoHNU325WHhXdhejVAItwObC
IpL/zYfs2+gDHXct/n9FJ/9D/EGXZihwPqYaK8GQSfZAxz0QjLuh0wU1qpbm3y3N
q+o9FLv3b2Ys/tCJOUsYVQOYLSrZEI77y1ii3nWgQ8lXiTJbBUKzuq4f1YWeO8Ah
RZbdhTa57AF5lUaRtL7Nrm3HJUrK1alBbU7HHyjeW4Q4n/D3fiRDC1Mh2Bi4EOOn
wGctSx4kHsZGhJv5qwKqqPEFPhUzph8D2tm2TABk8HJa5KJFDbGrcfvk2uODAoZr
MbcpIxCfl8oB09bWfY6tDQjyvwSYYo2Phdwm7kT92xc=
-----END RSA PRIVATE KEY-----`

	// knownHostsFixture is known_hosts fixture in the expected
	// format.
	knownHostsFixture string = `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`
)

func Test_transportAuth(t *testing.T) {
	tests := []struct {
		name     string
		opts     *git.AuthOptions
		wantFunc func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions)
		kexAlgos []string
		wantErr  error
	}{
		{
			name: "Public HTTP Repositories",
			opts: &git.AuthOptions{
				Transport: git.HTTP,
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				g.Expect(t).To(BeNil())
			},
		},
		{
			name: "Public HTTPS Repositories",
			opts: &git.AuthOptions{
				Transport: git.HTTP,
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				g.Expect(t).To(BeNil())
			},
		},
		{
			name: "HTTP basic auth",
			opts: &git.AuthOptions{
				Transport: git.HTTP,
				Username:  "example",
				Password:  "password",
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				g.Expect(t).To(Equal(&http.BasicAuth{
					Username: opts.Username,
					Password: opts.Password,
				}))
			},
		},
		{
			name: "HTTPS basic auth",
			opts: &git.AuthOptions{
				Transport: git.HTTPS,
				Username:  "example",
				Password:  "password",
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				g.Expect(t).To(Equal(&http.BasicAuth{
					Username: opts.Username,
					Password: opts.Password,
				}))
			},
		},
		{
			name: "SSH private key",
			opts: &git.AuthOptions{
				Transport: git.SSH,
				Username:  "example",
				Identity:  []byte(privateKeyFixture),
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				tt, ok := t.(*CustomPublicKeys)
				g.Expect(ok).To(BeTrue())
				g.Expect(tt.pk.User).To(Equal(opts.Username))
				g.Expect(tt.pk.Signer.PublicKey().Type()).To(Equal("ssh-rsa"))
			},
		},
		{
			name: "SSH private key with passphrase",
			opts: &git.AuthOptions{
				Transport: git.SSH,
				Username:  "example",
				Password:  "foobar",
				Identity:  []byte(privateKeyPassphraseFixture),
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				tt, ok := t.(*CustomPublicKeys)
				g.Expect(ok).To(BeTrue())
				g.Expect(tt.pk.User).To(Equal(opts.Username))
				g.Expect(tt.pk.Signer.PublicKey().Type()).To(Equal("ssh-rsa"))
			},
		},
		{
			name: "SSH with custom key exchanges",
			opts: &git.AuthOptions{
				Transport:  git.SSH,
				Username:   "example",
				Identity:   []byte(privateKeyFixture),
				KnownHosts: []byte(knownHostsFixture),
			},
			kexAlgos: []string{"curve25519-sha256", "diffie-hellman-group-exchange-sha256"},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				tt, ok := t.(*CustomPublicKeys)
				g.Expect(ok).To(BeTrue())
				g.Expect(tt.pk.User).To(Equal(opts.Username))
				g.Expect(tt.pk.Signer.PublicKey().Type()).To(Equal("ssh-rsa"))
				config, err := tt.ClientConfig()
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(config.Config.KeyExchanges).To(Equal(
					[]string{"curve25519-sha256", "diffie-hellman-group-exchange-sha256"}),
				)
			},
		},
		{
			name: "SSH private key with invalid passphrase",
			opts: &git.AuthOptions{
				Transport: git.SSH,
				Username:  "example",
				Password:  "",
				Identity:  []byte(privateKeyPassphraseFixture),
			},
			wantErr: errors.New("x509: decryption password incorrect"),
		},
		{
			name: "SSH private key with known_hosts",
			opts: &git.AuthOptions{
				Transport:  git.SSH,
				Username:   "example",
				Identity:   []byte(privateKeyFixture),
				KnownHosts: []byte(knownHostsFixture),
			},
			wantFunc: func(g *WithT, t transport.AuthMethod, opts *git.AuthOptions) {
				tt, ok := t.(*CustomPublicKeys)
				g.Expect(ok).To(BeTrue())
				g.Expect(tt.pk.User).To(Equal(opts.Username))
				g.Expect(tt.pk.Signer.PublicKey().Type()).To(Equal("ssh-rsa"))
				g.Expect(tt.pk.HostKeyCallback).ToNot(BeNil())
			},
		},
		{
			name: "SSH private key with invalid known_hosts",
			opts: &git.AuthOptions{
				Transport:  git.SSH,
				Username:   "example",
				Identity:   []byte(privateKeyFixture),
				KnownHosts: []byte("invalid"),
			},
			wantErr: errors.New("knownhosts: knownhosts: missing host pattern"),
		},
		{
			name:    "Empty",
			opts:    &git.AuthOptions{},
			wantErr: errors.New("no transport type set"),
		},
		{
			name: "Unknown transport",
			opts: &git.AuthOptions{
				Transport: "foo",
			},
			wantErr: errors.New("unknown transport 'foo'"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			if len(tt.kexAlgos) > 0 {
				git.KexAlgos = tt.kexAlgos
			}

			got, err := transportAuth(tt.opts)
			if tt.wantErr != nil {
				g.Expect(err).To(Equal(tt.wantErr))
				g.Expect(got).To(BeNil())
				return
			}
			g.Expect(err).ToNot(HaveOccurred())
			if tt.wantFunc != nil {
				tt.wantFunc(g, got, tt.opts)
			}
		})
	}
}

func Test_caBundle(t *testing.T) {
	g := NewWithT(t)

	g.Expect(caBundle(&git.AuthOptions{CAFile: []byte("foo")})).To(BeEquivalentTo("foo"))
	g.Expect(caBundle(nil)).To(BeNil())
}
