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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
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

func TestClientOptionsFromSecret(t *testing.T) {
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

			got, err := ClientOptionsFromSecret(secret)
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

func TestBasicAuthFromSecret(t *testing.T) {
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
			got, err := BasicAuthFromSecret(*secret)
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

func TestTLSClientConfigFromSecret(t *testing.T) {
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
