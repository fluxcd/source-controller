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

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func Test_tlsClientConfigFromSecret(t *testing.T) {
	kubernetesTlsSecretFixture := validTlsSecret(t, true)
	tlsSecretFixture := validTlsSecret(t, false)

	tests := []struct {
		name      string
		secret    corev1.Secret
		modify    func(secret *corev1.Secret)
		tlsKeys   bool
		checkType bool
		url       string
		wantErr   bool
		wantNil   bool
	}{
		{
			name:    "tls.crt, tls.key and ca.crt",
			secret:  kubernetesTlsSecretFixture,
			modify:  nil,
			tlsKeys: true,
			url:     "https://example.com",
		},
		{
			name:    "certFile, keyFile and caFile",
			secret:  tlsSecretFixture,
			modify:  nil,
			tlsKeys: false,
			url:     "https://example.com",
		},
		{
			name:    "without tls.crt",
			secret:  kubernetesTlsSecretFixture,
			modify:  func(s *corev1.Secret) { delete(s.Data, "tls.crt") },
			tlsKeys: true,
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "without tls.key",
			secret:  kubernetesTlsSecretFixture,
			modify:  func(s *corev1.Secret) { delete(s.Data, "tls.key") },
			tlsKeys: true,
			wantErr: true,
			wantNil: true,
		},
		{
			name:    "without ca.crt",
			secret:  kubernetesTlsSecretFixture,
			modify:  func(s *corev1.Secret) { delete(s.Data, "ca.crt") },
			tlsKeys: true,
		},
		{
			name:    "empty secret",
			secret:  corev1.Secret{},
			tlsKeys: true,
			wantNil: true,
		},
		{
			name:      "docker config secret with type checking enabled",
			secret:    tlsSecretFixture,
			modify:    func(secret *corev1.Secret) { secret.Type = corev1.SecretTypeDockerConfigJson },
			tlsKeys:   false,
			checkType: true,
			wantErr:   true,
			wantNil:   true,
		},
		{
			name:    "docker config secret with type checking disabled",
			secret:  tlsSecretFixture,
			modify:  func(secret *corev1.Secret) { secret.Type = corev1.SecretTypeDockerConfigJson },
			tlsKeys: false,
			url:     "https://example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			secret := tt.secret.DeepCopy()
			if tt.modify != nil {
				tt.modify(secret)
			}

			tlsConfig, _, err := tlsClientConfigFromSecret(*secret, tt.url, tt.tlsKeys, tt.checkType)
			g.Expect(err != nil).To(Equal(tt.wantErr), fmt.Sprintf("expected error: %v, got: %v", tt.wantErr, err))
			g.Expect(tlsConfig == nil).To(Equal(tt.wantNil))
			if tt.url != "" {
				u, _ := url.Parse(tt.url)
				g.Expect(u.Hostname()).To(Equal(tlsConfig.ServerName))
			}
		})
	}
}

// validTlsSecret creates a secret containing key pair and CA certificate that are
// valid from a syntax (minimum requirements) perspective.
func validTlsSecret(t *testing.T, kubernetesTlsKeys bool) corev1.Secret {
	t.Helper()
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

	crtKey := corev1.TLSCertKey
	pkKey := corev1.TLSPrivateKeyKey
	caKey := CACrtKey
	if !kubernetesTlsKeys {
		crtKey = "certFile"
		pkKey = "keyFile"
		caKey = "caFile"
	}
	return corev1.Secret{
		Data: map[string][]byte{
			crtKey: []byte(certPem),
			pkKey:  []byte(keyPem),
			caKey:  []byte(caPem),
		},
	}
}
