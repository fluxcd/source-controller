/*
Copyright 2026 The Flux authors

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

package notation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/notaryproject/notation-go/verifier/truststore"
	. "github.com/onsi/gomega"
)

func TestTrustStoreGetCertificates(t *testing.T) {
	newCert := func(name string) []byte {
		g := NewWithT(t)
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		g.Expect(err).ToNot(HaveOccurred())
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		g.Expect(err).ToNot(HaveOccurred())
		return der
	}
	toPEM := func(der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}

	first, second, third := newCert("first"), newCert("second"), newCert("third")

	tests := []struct {
		name    string
		certs   [][]byte
		want    []string
		wantErr bool
	}{
		{name: "single PEM", certs: [][]byte{toPEM(first)}, want: []string{"first"}},
		{name: "PEM bundle", certs: [][]byte{slices.Concat(toPEM(first), toPEM(second))}, want: []string{"first", "second"}},
		{name: "bundle and single entry", certs: [][]byte{slices.Concat(toPEM(first), toPEM(second)), toPEM(third)}, want: []string{"first", "second", "third"}},
		{name: "DER", certs: [][]byte{first}, want: []string{"first"}},
		{name: "invalid second block", certs: [][]byte{slices.Concat(toPEM(first), toPEM([]byte("invalid")))}, wantErr: true},
		{name: "invalid data", certs: [][]byte{[]byte("invalid")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			certs, err := trustStore{certs: tt.certs}.GetCertificates(context.Background(), truststore.TypeCA, "test")
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				return
			}

			g.Expect(err).ToNot(HaveOccurred())
			var names []string
			for _, cert := range certs {
				names = append(names, cert.Subject.CommonName)
			}
			g.Expect(names).To(Equal(tt.want))
		})
	}
}
