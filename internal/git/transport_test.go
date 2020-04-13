package git

import (
	"reflect"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	corev1 "k8s.io/api/core/v1"
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
)

func TestAuthMethodFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		secret  corev1.Secret
		want    transport.AuthMethod
		wantErr bool
	}{
		{"HTTP", "http://git.example.com/org/repo.git", basicAuthSecretFixture, &http.BasicAuth{}, false},
		{"HTTPS", "https://git.example.com/org/repo.git", basicAuthSecretFixture, &http.BasicAuth{}, false},
		{"SSH", "ssh://git.example.com:2222/org/repo.git", privateKeySecretFixture, &ssh.PublicKeys{}, false},
		{"unsupported", "protocol://git.example.com/org/repo.git", corev1.Secret{}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, cleanup, err := AuthMethodFromSecret(tt.url, tt.secret)
			if cleanup != nil {
				defer cleanup()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthMethodFromSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("AuthMethodFromSecret() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBasicAuthFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  corev1.Secret
		modify  func(secret *corev1.Secret)
		want    *http.BasicAuth
		wantErr bool
	}{
		{"username and password", basicAuthSecretFixture, nil, &http.BasicAuth{Username: "git", Password: "password"}, false},
		{"without username", basicAuthSecretFixture, func(s *corev1.Secret) { delete(s.Data, "username") }, nil, true},
		{"without password", basicAuthSecretFixture, func(s *corev1.Secret) { delete(s.Data, "password") }, nil, true},
		{"empty", corev1.Secret{}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}
			got, err := BasicAuthFromSecret(*secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("BasicAuthFromSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BasicAuthFromSecret() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKeysFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  corev1.Secret
		modify  func(secret *corev1.Secret)
		wantErr bool
	}{
		{"private key and known_hosts", privateKeySecretFixture, nil, false},
		{"missing private key", privateKeySecretFixture, func(s *corev1.Secret) { delete(s.Data, "identity") }, true},
		{"invalid private key", privateKeySecretFixture, func(s *corev1.Secret) { s.Data["identity"] = []byte(`-----BEGIN RSA PRIVATE KEY-----`) }, true},
		{"missing known_hosts", privateKeySecretFixture, func(s *corev1.Secret) { delete(s.Data, "known_hosts") }, true},
		{"invalid known_hosts", privateKeySecretFixture, func(s *corev1.Secret) { s.Data["known_hosts"] = []byte(`invalid`) }, true},
		{"empty", corev1.Secret{}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}
			_, cleanup, err := PublicKeysFromSecret(*secret)
			if cleanup != nil {
				defer cleanup()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKeysFromSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
