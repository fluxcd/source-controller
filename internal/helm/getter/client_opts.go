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
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/runtime/secrets"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/fluxcd/source-controller/internal/helm/registry"
	soci "github.com/fluxcd/source-controller/internal/oci"
)

const (
	certFileName = "cert.pem"
	keyFileName  = "key.pem"
	caFileName   = "ca.pem"
)

var ErrDeprecatedTLSConfig = errors.New("TLS configured in a deprecated manner")

// option applies configuration to ClientOpts.
type option func(*ClientOpts) error

// ClientOpts contains the various options to use while constructing
// a Helm repository client.
type ClientOpts struct {
	Authenticator authn.Authenticator
	Keychain      authn.Keychain
	RegLoginOpts  []helmreg.LoginOption
	TlsConfig     *tls.Config
	GetterOpts    []helmgetter.Option
	Insecure      bool
	CertsTempDir  string
}

// MustLoginToRegistry returns true if the client options contain at least
// one registry login option. This indicates that registry authentication
// has been configured, regardless of the specific login option type.
func (o ClientOpts) MustLoginToRegistry() bool {
	return len(o.RegLoginOpts) > 0
}

// GetClientOpts uses the provided HelmRepository object and a normalized
// URL to construct a HelmClientOpts object. If obj is an OCI HelmRepository,
// then the returned options object will also contain the required registry
// auth mechanisms.
// A temporary directory is created to store the certs files if needed and its path is available via ClientOpts.CertsTempDir.
// It is the caller's responsibility to clean up the directory.
func GetClientOpts(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, url string) (*ClientOpts, error) {
	var certSecret, authSecret *corev1.Secret
	var err error

	opts := &ClientOpts{
		GetterOpts: []helmgetter.Option{
			helmgetter.WithURL(url),
			helmgetter.WithTimeout(obj.GetTimeout()),
			helmgetter.WithPassCredentialsAll(obj.Spec.PassCredentials),
		},
		Insecure: obj.Spec.Insecure,
	}

	if obj.Spec.CertSecretRef != nil {
		certSecret, err = fetchSecret(ctx, c, obj.Spec.CertSecretRef.Name, obj.GetNamespace())
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.CertSecretRef.Name, err)
		}
		certOpt := withAuthFromCertSecret(ctx, certSecret, url, obj.Spec.Insecure)
		if err := certOpt(opts); err != nil {
			return nil, err
		}
	}

	var deprecatedErr error
	if obj.Spec.SecretRef != nil {
		authSecret, err = fetchSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			return nil, fmt.Errorf("failed to get authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.SecretRef.Name, err)
		}

		secretRefOpt := withAuthFromSecret(ctx, authSecret, url, obj.Spec.Insecure)
		if err := secretRefOpt(opts); err != nil {
			if errors.Is(err, ErrDeprecatedTLSConfig) {
				deprecatedErr = err
			} else {
				return nil, err
			}
		}
	}

	if obj.Spec.Type == sourcev1.HelmRepositoryTypeOCI {
		ociOpt := withOCIRegistry(ctx, obj, url, certSecret, authSecret)
		if err := ociOpt(opts); err != nil {
			return nil, err
		}
	}

	return opts, deprecatedErr
}

// withAuthFromCertSecret applies TLS config from a pre-fetched secret.
func withAuthFromCertSecret(ctx context.Context, secret *corev1.Secret, url string, insecure bool) option {
	return func(o *ClientOpts) error {
		tlsConfig, err := secrets.TLSConfigFromSecret(ctx, secret, url, insecure)
		if err != nil {
			return fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
		}
		o.TlsConfig = tlsConfig
		return nil
	}
}

// withAuthFromSecret applies BasicAuth or TLS from a pre-fetched secret.
// Returns ErrDeprecatedTLSConfig if TLS config comes from SecretRef (deprecated pattern).
func withAuthFromSecret(ctx context.Context, secret *corev1.Secret, url string, insecure bool) option {
	return func(o *ClientOpts) error {
		methods, err := secrets.AuthMethodsFromSecret(ctx, secret, secrets.WithTLS(url, insecure))
		if err != nil {
			return fmt.Errorf("failed to detect authentication methods: %w", err)
		}

		if methods.HasBasicAuth() {
			o.GetterOpts = append(o.GetterOpts,
				helmgetter.WithBasicAuth(methods.Basic.Username, methods.Basic.Password))
		}

		if o.TlsConfig == nil && methods.HasTLS() {
			o.TlsConfig = methods.TLS
			return ErrDeprecatedTLSConfig
		}
		return nil
	}
}

// withOCIRegistry applies OCI-specific login and TLS file handling.
func withOCIRegistry(ctx context.Context, obj *sourcev1.HelmRepository, url string, certSecret, authSecret *corev1.Secret) option {
	return func(o *ClientOpts) error {
		if authSecret != nil {
			keychain, err := registry.LoginOptionFromSecret(url, *authSecret)
			if err != nil {
				return fmt.Errorf("failed to configure login options: %w", err)
			}
			o.Keychain = keychain
		}

		if obj.Spec.SecretRef == nil && obj.Spec.Provider != "" && obj.Spec.Provider != sourcev1.GenericOCIProvider {
			authenticator, err := soci.OIDCAuth(ctx, url, obj.Spec.Provider)
			if err != nil {
				return fmt.Errorf("failed to get credential from '%s': %w", obj.Spec.Provider, err)
			}
			o.Authenticator = authenticator
		}

		loginOpt, err := registry.NewLoginOption(o.Authenticator, o.Keychain, url)
		if err != nil {
			return err
		}

		if loginOpt != nil {
			// NOTE: RegLoginOpts is rebuilt here intentionally (overwrites any existing entries).
			o.RegLoginOpts = []helmreg.LoginOption{loginOpt, helmreg.LoginOptInsecure(obj.Spec.Insecure)}
		}

		if o.TlsConfig != nil {
			tempCertDir, err := os.MkdirTemp("", "helm-repo-oci-certs")
			if err != nil {
				return fmt.Errorf("cannot create temporary directory: %w", err)
			}

			var tlsSecret *corev1.Secret
			if certSecret != nil {
				tlsSecret = certSecret
			} else if authSecret != nil {
				tlsSecret = authSecret
			}

			certFile, keyFile, caFile, err := storeTLSCertificateFilesForOCI(tlsSecret, nil, tempCertDir)
			if err != nil {
				return fmt.Errorf("cannot write certs files to path: %w", err)
			}

			tlsLoginOpt := registry.TLSLoginOption(certFile, keyFile, caFile)
			if tlsLoginOpt != nil {
				o.RegLoginOpts = append(o.RegLoginOpts, tlsLoginOpt)
			}

			o.CertsTempDir = tempCertDir
		}

		return nil
	}
}

func fetchSecret(ctx context.Context, c client.Client, name, namespace string) (*corev1.Secret, error) {
	key := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
	var secret corev1.Secret
	if err := c.Get(ctx, key, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

// storeTLSCertificateFilesForOCI writes TLS certificate data from secrets to files for OCI registry authentication.
// Helm OCI registry client requires certificate file paths rather than in-memory data,
// so we need to temporarily write the certificate data to disk.
// Returns paths to the written cert, key, and CA files (any of which may be empty if not present).
func storeTLSCertificateFilesForOCI(certSecret, authSecret *corev1.Secret, dir string) (string, string, string, error) {
	var (
		certFile string
		keyFile  string
		caFile   string
		err      error
	)

	var tlsSecret *corev1.Secret
	if certSecret != nil {
		tlsSecret = certSecret
	} else if authSecret != nil {
		tlsSecret = authSecret
	}

	if tlsSecret != nil {
		if certData, exists := tlsSecret.Data[secrets.KeyTLSCert]; exists {
			if keyData, keyExists := tlsSecret.Data[secrets.KeyTLSPrivateKey]; keyExists {
				certFile, err = writeToFile(certData, certFileName, dir)
				if err != nil {
					return "", "", "", err
				}
				keyFile, err = writeToFile(keyData, keyFileName, dir)
				if err != nil {
					return "", "", "", err
				}
			}
		}

		if caData, exists := tlsSecret.Data[secrets.KeyCACert]; exists {
			caFile, err = writeToFile(caData, caFileName, dir)
			if err != nil {
				return "", "", "", err
			}
		}
	}

	return certFile, keyFile, caFile, nil
}

func writeToFile(data []byte, filename, tmpDir string) (string, error) {
	file := filepath.Join(tmpDir, filename)
	err := os.WriteFile(file, data, 0o600)
	if err != nil {
		return "", err
	}
	return file, nil
}
