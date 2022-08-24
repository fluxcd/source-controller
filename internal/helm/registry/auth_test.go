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
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

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

func TestOIDCAdaptHelper(t *testing.T) {
	auth := &authn.Basic{
		Username: "flux",
		Password: "flux_password",
	}

	tests := []struct {
		name          string
		auth          authn.Authenticator
		expectedLogin bool
		wantErr       bool
	}{
		{
			name:          "Login from basic auth with empty auth",
			auth:          &authn.Basic{},
			expectedLogin: false,
			wantErr:       false,
		},
		{
			name:          "Login from basic auth",
			auth:          auth,
			expectedLogin: true,
			wantErr:       false,
		},
		{
			name:          "Login with missing password",
			auth:          &authn.Basic{Username: "flux"},
			expectedLogin: false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			loginOpt, err := OIDCAdaptHelper(tt.auth)
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
