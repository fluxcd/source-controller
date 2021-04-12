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
	"reflect"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport/http"
	corev1 "k8s.io/api/core/v1"

	"github.com/fluxcd/source-controller/pkg/git"
)

const (
	// secretKeyFixture is a randomly generated password less
	// 512bit RSA private key.
	secretKeyFixture string = `-----BEGIN RSA PRIVATE KEY-----
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

	// secretKeyFixture is a randomly generated
	// 512bit RSA private key with password foobar.
	secretPassphraseFixture = `-----BEGIN RSA PRIVATE KEY-----
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

var (
	basicAuthSecretFixture = corev1.Secret{
		Data: map[string][]byte{
			"username": []byte("git"),
			"password": []byte("password"),
		},
	}
	privateKeySecretFixture = corev1.Secret{
		Data: map[string][]byte{
			"identity":    []byte(secretKeyFixture),
			"known_hosts": []byte(knownHostsFixture),
		},
	}
	privateKeySecretWithPassphraseFixture = corev1.Secret{
		Data: map[string][]byte{
			"identity":    []byte(secretPassphraseFixture),
			"known_hosts": []byte(knownHostsFixture),
			"password":    []byte("foobar"),
		},
	}
)

func TestAuthSecretStrategyForURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    git.AuthSecretStrategy
		wantErr bool
	}{
		{"HTTP", "http://git.example.com/org/repo.git", &BasicAuth{}, false},
		{"HTTPS", "https://git.example.com/org/repo.git", &BasicAuth{}, false},
		{"SSH", "ssh://git.example.com:2222/org/repo.git", &PublicKeyAuth{}, false},
		{"SSH with username", "ssh://example@git.example.com:2222/org/repo.git", &PublicKeyAuth{user: "example"}, false},
		{"unsupported", "protocol://example.com", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthSecretStrategyForURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthSecretStrategyForURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthSecretStrategyForURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBasicAuthStrategy_Method(t *testing.T) {
	tests := []struct {
		name    string
		secret  corev1.Secret
		modify  func(secret *corev1.Secret)
		want    *git.Auth
		wantErr bool
	}{
		{"username and password", basicAuthSecretFixture, nil, &git.Auth{AuthMethod: &http.BasicAuth{Username: "git", Password: "password"}}, false},
		{"without username", basicAuthSecretFixture, func(s *corev1.Secret) { delete(s.Data, "username") }, nil, true},
		{"without password", basicAuthSecretFixture, func(s *corev1.Secret) { delete(s.Data, "password") }, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}
			s := &BasicAuth{}
			got, err := s.Method(*secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Method() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Method() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKeyStrategy_Method(t *testing.T) {
	tests := []struct {
		name    string
		secret  corev1.Secret
		modify  func(secret *corev1.Secret)
		wantErr bool
	}{
		{"private key and known_hosts", privateKeySecretFixture, nil, false},
		{"private key with passphrase and known_hosts", privateKeySecretWithPassphraseFixture, nil, false},
		{"missing private key", privateKeySecretFixture, func(s *corev1.Secret) { delete(s.Data, "identity") }, true},
		{"invalid private key", privateKeySecretFixture, func(s *corev1.Secret) { s.Data["identity"] = []byte(`-----BEGIN RSA PRIVATE KEY-----`) }, true},
		{"missing known_hosts", privateKeySecretFixture, func(s *corev1.Secret) { delete(s.Data, "known_hosts") }, true},
		{"invalid known_hosts", privateKeySecretFixture, func(s *corev1.Secret) { s.Data["known_hosts"] = []byte(`invalid`) }, true},
		{"missing password", privateKeySecretWithPassphraseFixture, func(s *corev1.Secret) { delete(s.Data, "password") }, true},
		{"wrong password", privateKeySecretWithPassphraseFixture, func(s *corev1.Secret) { s.Data["password"] = []byte("pass") }, true},
		{"empty", corev1.Secret{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}
			s := &PublicKeyAuth{}
			_, err := s.Method(*secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("Method() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
