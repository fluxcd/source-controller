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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
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
		name            string
		certSecret      *corev1.Secret
		authSecret      *corev1.Secret
		imagePullSecret *corev1.Secret
		serviceAccount  *corev1.ServiceAccount
		provider        string
		afterFunc       func(t *WithT, hcOpts *ClientOpts)
		oci             bool
		err             error
	}{
		{
			name: "HelmRepository with certSecretRef discards TLS config in secretRef",
			certSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ca-file",
				},
				Data: map[string][]byte{
					"caFile": tlsCA,
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
		{
			name: "OCI HelmRepository with serviceaccount name",
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sa",
				},
				ImagePullSecrets: []corev1.LocalObjectReference{
					{
						Name: "pull-secret",
					},
				},
			},
			imagePullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pull-secret",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"ghcr.io":{"username":"user","password":"pass","auth":"dXNlcjpwYXNz"}}}`),
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
		{
			name:     "OCI HelmRepository with serviceaccount name and provider (serviceaccount takes precedence)",
			provider: helmv1.AzureOCIProvider,
			serviceAccount: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-sa",
				},
				ImagePullSecrets: []corev1.LocalObjectReference{
					{
						Name: "pull-secret",
					},
				},
			},
			imagePullSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pull-secret",
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"ghcr.io":{"username":"user","password":"pass","auth":"dXNlcjpwYXNz"}}}`),
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

			helmRepo := &helmv1.HelmRepository{
				Spec: helmv1.HelmRepositorySpec{
					Provider: tt.provider,
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
			if tt.imagePullSecret != nil {
				clientBuilder.WithObjects(tt.imagePullSecret.DeepCopy())
			}
			if tt.serviceAccount != nil {
				clientBuilder.WithObjects(tt.serviceAccount.DeepCopy())
				helmRepo.Spec.ServiceAccountName = tt.serviceAccount.Name
			}
			c := clientBuilder.Build()

			clientOpts, err := GetClientOpts(context.TODO(), c, helmRepo, "https://ghcr.io/dummy")
			if tt.err != nil {
				g.Expect(err).To(Equal(tt.err))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
			tt.afterFunc(g, clientOpts)
		})
	}
}

func Test_tlsClientConfigFromSecret(t *testing.T) {
	tlsSecretFixture := validTlsSecret(t)

	tests := []struct {
		name    string
		secret  corev1.Secret
		modify  func(secret *corev1.Secret)
		wantErr bool
		wantNil bool
	}{
		{"certFile, keyFile and caFile", tlsSecretFixture, nil, false, false},
		{"without certFile", tlsSecretFixture, func(s *corev1.Secret) { delete(s.Data, "certFile") }, true, true},
		{"without keyFile", tlsSecretFixture, func(s *corev1.Secret) { delete(s.Data, "keyFile") }, true, true},
		{"without caFile", tlsSecretFixture, func(s *corev1.Secret) { delete(s.Data, "caFile") }, false, false},
		{"empty", corev1.Secret{}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}

			got, err := TLSClientConfigFromSecret(*secret, "")
			if (err != nil) != tt.wantErr {
				t.Errorf("TLSClientConfigFromSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantNil && got != nil {
				t.Error("TLSClientConfigFromSecret() != nil")
				return
			}
		})
	}
}

// validTlsSecret creates a secret containing key pair and CA certificate that are
// valid from a syntax (minimum requirements) perspective.
func validTlsSecret(t *testing.T) corev1.Secret {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Private key cannot be created.", err.Error())
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1337),
	}
	cert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal("Certificate cannot be created.", err.Error())
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(7331),
		IsCA:         true,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal("CA private key cannot be created.", err.Error())
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatal("CA certificate cannot be created.", err.Error())
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	caPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return corev1.Secret{
		Data: map[string][]byte{
			"certFile": []byte(certPem),
			"keyFile":  []byte(keyPem),
			"caFile":   []byte(caPem),
		},
	}
}
