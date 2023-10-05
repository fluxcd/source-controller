/*
Copyright 2023 The Flux authors

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
	"context"
	qhelm "github.com/hossainemruz/qdrant-cloud-apis/api/helm/v1"
	"os"
	"testing"
	"time"

	"github.com/fluxcd/pkg/apis/meta"
	"github.com/google/go-containerregistry/pkg/name"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
)

func TestGetClientOpts(t *testing.T) {
	tlsCA, err := os.ReadFile("../../controller/testdata/certs/ca.pem")
	if err != nil {
		t.Errorf("could not read CA file: %s", err)
	}

	tests := []struct {
		name       string
		certSecret *corev1.Secret
		authSecret *corev1.Secret
		afterFunc  func(t *WithT, hcOpts *ClientOpts)
		oci        bool
		err        error
	}{
		{
			name: "HelmRepository with certSecretRef discards TLS config in secretRef",
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"ca.crt": tlsCA,
				},
			},
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
					"caFile":   []byte("invalid"),
				},
			},
			afterFunc: func(t *WithT, hcOpts *ClientOpts) {
				t.Expect(hcOpts.TlsConfig).ToNot(BeNil())
				t.Expect(len(hcOpts.GetterOpts)).To(Equal(4))
			},
		},
		{
			name: "HelmRepository with TLS config only in secretRef is marked as deprecated",
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-tls",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
					"caFile":   tlsCA,
				},
			},
			afterFunc: func(t *WithT, hcOpts *ClientOpts) {
				t.Expect(hcOpts.TlsConfig).ToNot(BeNil())
				t.Expect(len(hcOpts.GetterOpts)).To(Equal(4))
			},
			err: ErrDeprecatedTLSConfig,
		},
		{
			name: "OCI HelmRepository with secretRef has auth configured",
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-oci",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			afterFunc: func(t *WithT, hcOpts *ClientOpts) {
				repo, err := name.NewRepository("ghcr.io/dummy")
				t.Expect(err).ToNot(HaveOccurred())
				authenticator, err := hcOpts.Keychain.Resolve(repo)
				t.Expect(err).ToNot(HaveOccurred())
				config, err := authenticator.Authorization()
				t.Expect(err).ToNot(HaveOccurred())
				t.Expect(config.Username).To(Equal("user"))
				t.Expect(config.Password).To(Equal("pass"))
			},
			oci: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			helmRepo := &qhelm.HelmRepository{
				Spec: helmv1.HelmRepositorySpec{
					Timeout: &metav1.Duration{
						Duration: time.Second,
					},
				},
			}
			if tt.oci {
				helmRepo.Spec.Type = helmv1.HelmRepositoryTypeOCI
			}

			clientBuilder := fakeclient.NewClientBuilder()
			if tt.authSecret != nil {
				clientBuilder.WithObjects(tt.authSecret.DeepCopy())
				helmRepo.Spec.SecretRef = &meta.LocalObjectReference{
					Name: tt.authSecret.Name,
				}
			}
			if tt.certSecret != nil {
				clientBuilder.WithObjects(tt.certSecret.DeepCopy())
				helmRepo.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: tt.certSecret.Name,
				}
			}
			c := clientBuilder.Build()

			clientOpts, _, err := GetClientOpts(context.TODO(), c, helmRepo, "https://ghcr.io/dummy")
			if tt.err != nil {
				g.Expect(err).To(Equal(tt.err))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			tt.afterFunc(g, clientOpts)
		})
	}
}

func TestGetClientOpts_registryTLSLoginOption(t *testing.T) {
	tlsCA, err := os.ReadFile("../../controller/testdata/certs/ca.pem")
	if err != nil {
		t.Errorf("could not read CA file: %s", err)
	}

	tests := []struct {
		name       string
		certSecret *corev1.Secret
		authSecret *corev1.Secret
		loginOptsN int
	}{
		{
			name: "with valid caFile",
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"ca.crt": tlsCA,
				},
			},
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-oci",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			loginOptsN: 2,
		},
		{
			name: "without caFile",
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{},
			},
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-oci",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			loginOptsN: 1,
		},
		{
			name:       "without cert secret",
			certSecret: nil,
			authSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "auth-oci",
				},
				Data: map[string][]byte{
					"username": []byte("user"),
					"password": []byte("pass"),
				},
			},
			loginOptsN: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helmRepo := &qhelm.HelmRepository{
				Spec: helmv1.HelmRepositorySpec{
					Timeout: &metav1.Duration{
						Duration: time.Second,
					},
					Type: helmv1.HelmRepositoryTypeOCI,
				},
			}

			clientBuilder := fakeclient.NewClientBuilder()

			if tt.authSecret != nil {
				clientBuilder.WithObjects(tt.authSecret.DeepCopy())
				helmRepo.Spec.SecretRef = &meta.LocalObjectReference{
					Name: tt.authSecret.Name,
				}
			}

			if tt.certSecret != nil {
				clientBuilder.WithObjects(tt.certSecret.DeepCopy())
				helmRepo.Spec.CertSecretRef = &meta.LocalObjectReference{
					Name: tt.certSecret.Name,
				}
			}
			c := clientBuilder.Build()

			clientOpts, tmpDir, err := GetClientOpts(context.TODO(), c, helmRepo, "https://ghcr.io/dummy")
			if err != nil {
				t.Errorf("GetClientOpts() error = %v", err)
				return
			}
			if tmpDir != "" {
				defer os.RemoveAll(tmpDir)
			}
			if tt.loginOptsN != len(clientOpts.RegLoginOpts) {
				// we should have a login option but no TLS option
				t.Error("registryTLSLoginOption() != nil")
				return
			}
		})
	}
}
