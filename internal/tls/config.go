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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	neturl "net/url"

	corev1 "k8s.io/api/core/v1"
)

const CACrtKey = "ca.crt"

// TLSBytes contains the bytes of the TLS files.
type TLSBytes struct {
	// CertBytes is the bytes of the certificate file.
	CertBytes []byte
	// KeyBytes is the bytes of the key file.
	KeyBytes []byte
	// CABytes is the bytes of the CA file.
	CABytes []byte
}

// KubeTLSClientConfigFromSecret returns a TLS client config as a `tls.Config`
// object and in its bytes representation. The secret is expected to have the
// following keys:
// - tls.key, for the private key
// - tls.crt, for the certificate
// - ca.crt, for the CA certificate
//
// Secrets with no certificate, private key, AND CA cert are ignored. If only a
// certificate OR private key is found, an error is returned. The Secret type
// can be blank, Opaque or kubernetes.io/tls.
func KubeTLSClientConfigFromSecret(secret corev1.Secret, url string) (*tls.Config, *TLSBytes, error) {
	return tlsClientConfigFromSecret(secret, url, true, true)
}

// TLSClientConfigFromSecret returns a TLS client config as a `tls.Config`
// object and in its bytes representation. The secret is expected to have the
// following keys:
// - keyFile, for the private key
// - certFile, for the certificate
// - caFile, for the CA certificate
//
// Secrets with no certificate, private key, AND CA cert are ignored. If only a
// certificate OR private key is found, an error is returned. The Secret type
// can be blank, Opaque or kubernetes.io/tls.
func TLSClientConfigFromSecret(secret corev1.Secret, url string) (*tls.Config, *TLSBytes, error) {
	return tlsClientConfigFromSecret(secret, url, false, true)
}

// LegacyTLSClientConfigFromSecret returns a TLS client config as a `tls.Config`
// object and in its bytes representation. The secret is expected to have the
// following keys:
// - keyFile, for the private key
// - certFile, for the certificate
// - caFile, for the CA certificate
//
// Secrets with no certificate, private key, AND CA cert are ignored. If only a
// certificate OR private key is found, an error is returned.
func LegacyTLSClientConfigFromSecret(secret corev1.Secret, url string) (*tls.Config, *TLSBytes, error) {
	return tlsClientConfigFromSecret(secret, url, false, false)
}

// tlsClientConfigFromSecret attempts to construct and return a TLS client
// config from the given Secret. If the Secret does not contain any TLS
// data, it returns nil.
//
// kubernetesTLSKeys is a boolean indicating whether to check the Secret
// for keys expected to be present in a Kubernetes TLS Secret. Based on its
// value, the Secret is checked for the following keys:
// - tls.key/keyFile for the private key
// - tls.crt/certFile for the certificate
// - ca.crt/caFile for the CA certificate
// The keys should adhere to a single convention, i.e. a Secret with tls.key
// and certFile is invalid.
//
// checkType is a boolean indicating whether to check the Secret type. If true
// and the Secret's type is not blank, Opaque or kubernetes.io/tls, then an
// error is returned.
func tlsClientConfigFromSecret(secret corev1.Secret, url string, kubernetesTLSKeys bool, checkType bool) (*tls.Config, *TLSBytes, error) {
	if checkType {
		// Only Secrets of type Opaque and TLS are allowed. We also allow Secrets with a blank
		// type, to avoid having to specify the type of the Secret for every test case.
		// Since a real Kubernetes Secret is of type Opaque by default, its safe to allow this.
		switch secret.Type {
		case corev1.SecretTypeOpaque, corev1.SecretTypeTLS, "":
		default:
			return nil, nil, fmt.Errorf("cannot use secret '%s' to construct TLS config: invalid secret type: '%s'", secret.Name, secret.Type)
		}
	}

	var certBytes, keyBytes, caBytes []byte
	if kubernetesTLSKeys {
		certBytes, keyBytes, caBytes = secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey], secret.Data[CACrtKey]
	} else {
		certBytes, keyBytes, caBytes = secret.Data["certFile"], secret.Data["keyFile"], secret.Data["caFile"]
	}

	switch {
	case len(certBytes)+len(keyBytes)+len(caBytes) == 0:
		return nil, nil, nil
	case (len(certBytes) > 0 && len(keyBytes) == 0) || (len(keyBytes) > 0 && len(certBytes) == 0):
		return nil, nil, fmt.Errorf("invalid '%s' secret data: both certificate and private key need to be provided",
			secret.Name)
	}

	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if len(certBytes) > 0 && len(keyBytes) > 0 {
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, nil, err
		}
		tlsConf.Certificates = append(tlsConf.Certificates, cert)
	}

	if len(caBytes) > 0 {
		cp, err := x509.SystemCertPool()
		if err != nil {
			return nil, nil, fmt.Errorf("cannot retrieve system certificate pool: %w", err)
		}
		if !cp.AppendCertsFromPEM(caBytes) {
			return nil, nil, fmt.Errorf("cannot append certificate into certificate pool: invalid CA certificate")
		}

		tlsConf.RootCAs = cp
	}

	if url != "" {
		u, err := neturl.Parse(url)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse repository URL: %w", err)
		}

		tlsConf.ServerName = u.Hostname()
	}

	return tlsConf, &TLSBytes{
		CertBytes: certBytes,
		KeyBytes:  keyBytes,
		CABytes:   caBytes,
	}, nil
}
