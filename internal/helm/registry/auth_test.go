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

package registry

import (
	"context"
	"net/url"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const repoURL = "https://example.com"

// TODO: Consider consolidating this test with TestLoginOptionFromSecretRef to eliminate code duplication
// during a future refactoring. Currently kept separate to match the function separation.
func TestLoginOptionFromSecret(t *testing.T) {
	testURL := "oci://registry.example.com/foo/bar"
	testUser := "flux"
	testPassword := "somepassword"
	testDockerconfigjson := `{"auths":{"registry.example.com":{"username":"flux","password":"somepassword","auth":"Zmx1eDpzb21lcGFzc3dvcmQ="}}}`
	testDockerconfigjsonHTTPS := `{"auths":{"https://registry.example.com":{"username":"flux","password":"somepassword","auth":"Zmx1eDpzb21lcGFzc3dvcmQ="}}}`
	dockerconfigjsonKey := ".dockerconfigjson"

	tests := []struct {
		name       string
		url        string
		secretType corev1.SecretType
		secretData map[string][]byte
		wantErr    bool
	}{
		{
			name:       "generic secret",
			url:        testURL,
			secretType: corev1.SecretTypeOpaque,
			secretData: map[string][]byte{
				"username": []byte(testUser),
				"password": []byte(testPassword),
			},
		},
		{
			name:       "generic secret without username",
			url:        testURL,
			secretType: corev1.SecretTypeOpaque,
			secretData: map[string][]byte{
				"password": []byte(testPassword),
			},
			wantErr: true,
		},
		{
			name:       "generic secret without password",
			url:        testURL,
			secretType: corev1.SecretTypeOpaque,
			secretData: map[string][]byte{
				"username": []byte(testUser),
			},
			wantErr: true,
		},
		{
			name:       "generic secret without username and password",
			url:        testURL,
			secretType: corev1.SecretTypeOpaque,
		},
		{
			name:       "docker-registry secret",
			url:        testURL,
			secretType: corev1.SecretTypeDockerConfigJson,
			secretData: map[string][]byte{
				dockerconfigjsonKey: []byte(testDockerconfigjson),
			},
		},
		{
			name:       "docker-registry secret host mismatch",
			url:        "oci://registry.gitlab.com",
			secretType: corev1.SecretTypeDockerConfigJson,
			secretData: map[string][]byte{
				dockerconfigjsonKey: []byte(testDockerconfigjson),
			},
			wantErr: true,
		},
		{
			name:       "docker-registry secret invalid host",
			url:        "oci://registry .gitlab.com",
			secretType: corev1.SecretTypeDockerConfigJson,
			secretData: map[string][]byte{
				dockerconfigjsonKey: []byte(testDockerconfigjson),
			},
			wantErr: true,
		},
		{
			name:       "docker-registry secret invalid docker config",
			url:        testURL,
			secretType: corev1.SecretTypeDockerConfigJson,
			secretData: map[string][]byte{
				dockerconfigjsonKey: []byte("foo"),
			},
			wantErr: true,
		},
		{
			name:       "docker-registry secret with URL scheme",
			url:        testURL,
			secretType: corev1.SecretTypeDockerConfigJson,
			secretData: map[string][]byte{
				dockerconfigjsonKey: []byte(testDockerconfigjsonHTTPS),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			secret := corev1.Secret{}
			secret.Name = "test-secret"
			secret.Data = tt.secretData
			secret.Type = tt.secretType

			_, err := LoginOptionFromSecret(tt.url, secret)
			g.Expect(err != nil).To(Equal(tt.wantErr))
		})
	}
}

func TestLoginOptionFromSecretRef(t *testing.T) {
	testURL := "oci://registry.example.com/foo/bar"
	testUser := "flux"
	testPassword := "somepassword"
	testDockerconfigjson := `{"auths":{"registry.example.com":{"username":"flux","password":"somepassword","auth":"Zmx1eDpzb21lcGFzc3dvcmQ="}}}`
	testDockerconfigjsonHTTPS := `{"auths":{"https://registry.example.com":{"username":"flux","password":"somepassword","auth":"Zmx1eDpzb21lcGFzc3dvcmQ="}}}`

	tests := []struct {
		name    string
		url     string
		secret  *corev1.Secret
		wantErr bool
	}{
		{
			name:   "generic secret",
			url:    testURL,
			secret: newSecret(withGenericSecret(testUser, testPassword)),
		},
		{
			name:   "generic secret without username",
			url:    testURL,
			secret: newSecret(withPasswordOnly(testPassword)),
		},
		{
			name:   "generic secret without password",
			url:    testURL,
			secret: newSecret(withUsernameOnly(testUser)),
		},
		{
			name:   "generic secret without username and password",
			url:    testURL,
			secret: newSecret(withEmptyData()),
		},
		{
			name:   "docker-registry secret",
			url:    testURL,
			secret: newSecret(withDockerConfigSecret(testDockerconfigjson)),
		},
		{
			name:    "docker-registry secret host mismatch",
			url:     "oci://registry.gitlab.com",
			secret:  newSecret(withDockerConfigSecret(testDockerconfigjson)),
			wantErr: true,
		},
		{
			name:    "docker-registry secret invalid host",
			url:     "oci://registry .gitlab.com",
			secret:  newSecret(withDockerConfigSecret(testDockerconfigjson)),
			wantErr: true,
		},
		{
			name:    "docker-registry secret invalid docker config",
			url:     testURL,
			secret:  newSecret(withDockerConfigSecret("foo")),
			wantErr: true,
		},
		{
			name:   "docker-registry secret with URL scheme",
			url:    testURL,
			secret: newSecret(withDockerConfigSecret(testDockerconfigjsonHTTPS)),
		},
		{
			name:    "secret not found",
			url:     testURL,
			secret:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			ctx := context.TODO()

			var objs []client.Object
			if tt.secret != nil {
				objs = append(objs, tt.secret)
			}

			c := fakeclient.NewClientBuilder().WithObjects(objs...).Build()

			_, err := LoginOptionFromSecretRef(ctx, c, tt.url, "test-secret", "default")
			g.Expect(err != nil).To(Equal(tt.wantErr))
		})
	}
}

func TestKeychainAdaptHelper(t *testing.T) {
	g := NewWithT(t)
	reg, err := url.Parse(repoURL)
	if err != nil {
		g.Expect(err).ToNot(HaveOccurred())
	}

	auth := helper{
		username: "flux",
		password: "flux_password",
		registry: reg.Host,
	}

	tests := []struct {
		name          string
		auth          authn.Keychain
		expectedLogin bool
		wantErr       bool
	}{
		{
			name:          "Login from basic auth with empty auth",
			auth:          authn.NewKeychainFromHelper(helper{}),
			expectedLogin: false,
			wantErr:       false,
		},
		{
			name:          "Login from basic auth",
			auth:          authn.NewKeychainFromHelper(auth),
			expectedLogin: true,
			wantErr:       false,
		},
		{
			name:          "Login with missing password",
			auth:          authn.NewKeychainFromHelper(helper{username: "flux", registry: reg.Host}),
			expectedLogin: false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			loginOpt, err := KeychainAdaptHelper(tt.auth)(repoURL)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}
			g.Expect(err).To(BeNil())

			if tt.expectedLogin {
				g.Expect(loginOpt).ToNot(BeNil())
			} else {
				g.Expect(loginOpt).To(BeNil())
			}
		})
	}
}

type secretOption func(*corev1.Secret)

func withGenericSecret(username, password string) secretOption {
	return func(s *corev1.Secret) {
		s.Type = corev1.SecretTypeOpaque
		s.Data = map[string][]byte{
			"username": []byte(username),
			"password": []byte(password),
		}
	}
}

func withUsernameOnly(username string) secretOption {
	return func(s *corev1.Secret) {
		s.Type = corev1.SecretTypeOpaque
		s.Data = map[string][]byte{
			"username": []byte(username),
		}
	}
}

func withPasswordOnly(password string) secretOption {
	return func(s *corev1.Secret) {
		s.Type = corev1.SecretTypeOpaque
		s.Data = map[string][]byte{
			"password": []byte(password),
		}
	}
}

func withDockerConfigSecret(dockerConfig string) secretOption {
	return func(s *corev1.Secret) {
		s.Type = corev1.SecretTypeDockerConfigJson
		s.Data = map[string][]byte{
			".dockerconfigjson": []byte(dockerConfig),
		}
	}
}

func withEmptyData() secretOption {
	return func(s *corev1.Secret) {
		s.Type = corev1.SecretTypeOpaque
		s.Data = map[string][]byte{}
	}
}

func newSecret(opts ...secretOption) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
	}
	for _, opt := range opts {
		opt(secret)
	}
	return secret
}
