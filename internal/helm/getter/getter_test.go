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

package getter

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

var (
	basicAuthSecretFixture = corev1.Secret{
		Data: map[string][]byte{
			"username": []byte("user"),
			"password": []byte("password"),
		},
	}
)

func TestGetterOptionsFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secrets []corev1.Secret
	}{
		{"basic auth", []corev1.Secret{basicAuthSecretFixture}},
		{"empty", []corev1.Secret{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := corev1.Secret{Data: map[string][]byte{}}
			for _, s := range tt.secrets {
				for k, v := range s.Data {
					secret.Data[k] = v
				}
			}

			got, err := GetterOptionsFromSecret(secret)
			if err != nil {
				t.Errorf("ClientOptionsFromSecret() error = %v", err)
				return
			}
			if len(got) != len(tt.secrets) {
				t.Errorf("ClientOptionsFromSecret() options = %v, expected = %v", got, len(tt.secrets))
			}
		})
	}
}

func Test_basicAuthFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  corev1.Secret
		modify  func(secret *corev1.Secret)
		wantErr bool
		wantNil bool
	}{
		{"username and password", basicAuthSecretFixture, nil, false, false},
		{"without username", basicAuthSecretFixture, func(s *corev1.Secret) { delete(s.Data, "username") }, true, true},
		{"without password", basicAuthSecretFixture, func(s *corev1.Secret) { delete(s.Data, "password") }, true, true},
		{"empty", corev1.Secret{}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}
			got, err := basicAuthFromSecret(*secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("BasicAuthFromSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantNil && got != nil {
				t.Error("BasicAuthFromSecret() != nil")
				return
			}
		})
	}
}
