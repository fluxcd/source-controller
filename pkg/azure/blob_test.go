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

package azure

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

func TestValidateSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *corev1.Secret
		wantErr bool
	}{
		{
			name: "valid UserManagedIdentity Secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					clientIDField: []byte("some-client-id-"),
				},
			},
		},
		{
			name: "valid ServicePrincipal Certificate Secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					tenantIDField:          []byte("some-tenant-id-"),
					clientIDField:          []byte("some-client-id-"),
					clientCertificateField: []byte("some-certificate"),
				},
			},
		},
		{
			name: "valid ServicePrincipal Secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					tenantIDField:     []byte("some-tenant-id-"),
					clientIDField:     []byte("some-client-id-"),
					clientSecretField: []byte("some-client-secret-"),
				},
			},
		},
		{
			name: "valid SAS Key Secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					sasKeyField: []byte("?spr=<some-sas-url"),
				},
			},
		},
		{
			name: "valid SharedKey Secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					accountKeyField: []byte("some-account-key"),
				},
			},
		},
		{
			name: "valid AuthorityHost Secret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					authorityHostField: []byte("some.host.com"),
				},
			},
		},
		{
			name: "invalid ServicePrincipal Secret with missing ClientID and ClientSecret",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					tenantIDField: []byte("some-tenant-id-"),
				},
			},
			wantErr: true,
		},
		{
			name:    "invalid empty secret",
			secret:  &corev1.Secret{},
			wantErr: true,
		},
		{
			name:   "valid nil secret",
			secret: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			want := BeNil()
			if tt.wantErr {
				want = HaveOccurred()
			}
			g.Expect(ValidateSecret(tt.secret)).To(want)
		})
	}
}

func TestBlobClient_ObjectIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "StorageError with BlobNotFound code",
			err:  &azblob.StorageError{ErrorCode: azblob.StorageErrorCodeBlobNotFound},
			want: true,
		},
		{
			name: "StorageError with different code",
			err:  &azblob.StorageError{ErrorCode: azblob.StorageErrorCodeInternalError},
		},
		{
			name: "other error",
			err:  errors.New("an error"),
		},
		{
			name: "nil error",
			err:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			c := &BlobClient{}
			g.Expect(c.ObjectIsNotFound(tt.err)).To(Equal(tt.want))
		})
	}
}

func Test_extractAccountNameFromEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
		wantErr  bool
	}{
		{
			name:     "returns account name for endpoint",
			endpoint: "https://foo.blob.core.windows.net",
			want:     "foo",
		},
		{
			name:     "error for endpoint URL parse err",
			endpoint: "#http//foo.blob.core.windows.net",
			wantErr:  true,
		},
		{
			name:     "error for endpoint URL without subdomain",
			endpoint: "https://windows.net",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got, err := extractAccountNameFromEndpoint(tt.endpoint)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func Test_tokenCredentialFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *corev1.Secret
		want    azcore.TokenCredential
		wantErr bool
	}{
		{
			name: "with ClientID field",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					clientIDField: []byte("client-id"),
				},
			},
			want: &azidentity.ManagedIdentityCredential{},
		},
		{
			name: "with TenantID, ClientID and ClientCertificate fields",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					clientIDField:          []byte("client-id"),
					tenantIDField:          []byte("tenant-id"),
					clientCertificateField: validTls(t),
				},
			},
			want: &azidentity.ClientCertificateCredential{},
		},
		{
			name: "with TenantID, ClientID and ClientSecret fields",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					clientIDField:     []byte("client-id"),
					tenantIDField:     []byte("tenant-id"),
					clientSecretField: []byte("client-secret"),
				},
			},
			want: &azidentity.ClientSecretCredential{},
		},
		{
			name:   "empty secret",
			secret: &corev1.Secret{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := tokenCredentialFromSecret(tt.secret)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			if tt.want != nil {
				g.Expect(got).ToNot(BeNil())
				g.Expect(got).To(BeAssignableToTypeOf(tt.want))
				return
			}
			g.Expect(got).To(BeNil())
		})
	}
}

func Test_sharedCredentialFromSecret(t *testing.T) {
	var testKey = []byte("dGVzdA==")
	tests := []struct {
		name     string
		endpoint string
		secret   *corev1.Secret
		want     *azblob.SharedKeyCredential
		wantErr  bool
	}{
		{
			name:     "with AccountKey field",
			endpoint: "https://some.endpoint.com",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					accountKeyField: testKey,
				},
			},
			want: &azblob.SharedKeyCredential{},
		},
		{
			name:     "invalid endpoint",
			endpoint: "#http//some.endpoint.com",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					accountKeyField: testKey,
				},
			},
			wantErr: true,
		},
		{
			name:   "empty secret",
			secret: &corev1.Secret{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := sharedCredentialFromSecret(tt.endpoint, tt.secret)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			if tt.want != nil {
				g.Expect(got).ToNot(BeNil())
				g.Expect(got).To(BeAssignableToTypeOf(tt.want))
				return
			}
			g.Expect(got).To(BeNil())
		})
	}
}

func Test_sasTokenFromSecret(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		secret   *corev1.Secret
		want     string
		wantErr  bool
	}{
		{
			name:     "Valid SAS Token",
			endpoint: "https://accountName.blob.windows.net",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					sasKeyField: []byte("?sv=2020-08-0&ss=bfqt&srt=co&sp=rwdlacupitfx&se=2022-05-26T21:55:35Z&st=2022-05-26T13:55:35Z&spr=https&sig=JlHT"),
				},
			},
			want: "https://accountName.blob.windows.net?sv=2020-08-0&ss=bfqt&srt=co&sp=rwdlacupitfx&se=2022-05-26T21:55:35Z&st=2022-05-26T13:55:35Z&spr=https&sig=JlHT",
		},
		{
			name:     "Valid SAS Token without leading question mark",
			endpoint: "https://accountName.blob.windows.net",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					sasKeyField: []byte("sv=2020-08-04&ss=bfqt&srt=co&sp=rwdl&se=2022-05-26T21:55:35Z&st=2022-05-26&spr=https&sig=JlHT"),
				},
			},
			want: "https://accountName.blob.windows.net?sv=2020-08-04&ss=bfqt&srt=co&sp=rwdl&se=2022-05-26T21:55:35Z&st=2022-05-26&spr=https&sig=JlHT",
		},
		{
			name:     "endpoint with query values",
			endpoint: "https://accountName.blob.windows.net?sv=2020-08-04",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					sasKeyField: []byte("ss=bfqt&srt=co&sp=rwdl&se=2022-05-26T21:55:35Z&st=2022-05-26&spr=https&sig=JlHT"),
				},
			},
			want: "https://accountName.blob.windows.net?sv=2020-08-04&ss=bfqt&srt=co&sp=rwdl&se=2022-05-26T21:55:35Z&st=2022-05-26&spr=https&sig=JlHT",
		},
		{
			name:     "conflicting query values in token",
			endpoint: "https://accountName.blob.windows.net?sv=2020-08-04&ss=abcde",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					sasKeyField: []byte("sv=2019-07-06&ss=bfqt&srt=co&sp=rwdl&se=2022-05-26T21:55:35Z&st=2022-05-26&spr=https&sig=JlHT"),
				},
			},
			want: "https://accountName.blob.windows.net?sv=2019-07-06&ss=bfqt&srt=co&sp=rwdl&se=2022-05-26T21:55:35Z&st=2022-05-26&spr=https&sig=JlHT",
		},
		{
			name: "invalid sas token",
			secret: &corev1.Secret{
				Data: map[string][]byte{
					sasKeyField: []byte("%##sssvecrpt"),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			_, err := url.ParseQuery("")
			got, err := sasTokenFromSecret(tt.endpoint, tt.secret)
			g.Expect(err != nil).To(Equal(tt.wantErr))
			if tt.want != "" {
				ttVaules, err := url.Parse(tt.want)
				g.Expect(err).To(BeNil())

				gotValues, err := url.Parse(got)
				g.Expect(err).To(BeNil())
				g.Expect(gotValues.Query()).To(Equal(ttVaules.Query()))
				return
			}
			g.Expect(got).To(Equal(""))
		})
	}
}

func Test_chainCredentialWithSecret(t *testing.T) {
	g := NewWithT(t)

	got, err := chainCredentialWithSecret(nil)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got).To(BeAssignableToTypeOf(&azidentity.ChainedTokenCredential{}))
}

func Test_extractAccountNameFromEndpoint1(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
		wantErr  string
	}{
		{
			name:     "valid URL",
			endpoint: endpointURL("foo"),
			want:     "foo",
		},
		{
			name:     "URL parse error",
			endpoint: " https://example.com",
			wantErr:  "first path segment in URL cannot contain colon",
		},
		{
			name:     "error on non subdomain",
			endpoint: "https://example.com",
			wantErr:  "expected 'example.com' to be a subdomain",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			got, err := extractAccountNameFromEndpoint(tt.endpoint)
			if tt.wantErr != "" {
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
				g.Expect(got).To(BeEmpty())
				return
			}
			g.Expect(err).To(BeNil())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func endpointURL(accountName string) string {
	return fmt.Sprintf("https://%s.blob.core.windows.net", accountName)
}

func validTls(t *testing.T) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Private key cannot be created.", err.Error())
	}

	out := bytes.NewBuffer(nil)

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err = pem.Encode(out, privateKey); err != nil {
		t.Fatal("Private key cannot be PEM encoded.", err.Error())
	}

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1337),
	}
	cert, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal("Certificate cannot be created.", err.Error())
	}
	var certificate = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	if err = pem.Encode(out, certificate); err != nil {
		t.Fatal("Certificate cannot be PEM encoded.", err.Error())
	}

	return out.Bytes()
}
