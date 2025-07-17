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
	"path"

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

// ClientOpts contains the various options to use while constructing
// a Helm repository client.
type ClientOpts struct {
	Authenticator authn.Authenticator
	Keychain      authn.Keychain
	RegLoginOpts  []helmreg.LoginOption
	TlsConfig     *tls.Config
	GetterOpts    []helmgetter.Option
	Insecure      bool
}

// MustLoginToRegistry returns true if the client options contain at least
// one registry login option.
func (o ClientOpts) MustLoginToRegistry() bool {
	return len(o.RegLoginOpts) > 0 && o.RegLoginOpts[0] != nil
}

// GetClientOpts uses the provided HelmRepository object and a normalized
// URL to construct a HelmClientOpts object. If obj is an OCI HelmRepository,
// then the returned options object will also contain the required registry
// auth mechanisms.
// A temporary directory is created to store the certs files if needed and its path is returned along with the options object. It is the
// caller's responsibility to clean up the directory.
func GetClientOpts(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, url string) (*ClientOpts, string, error) {
	// This function configures authentication for Helm repositories based on the provided secrets:
	// - CertSecretRef: TLS client certificates (always takes priority)
	// - SecretRef: Can contain Basic Auth or TLS certificates (deprecated)
	// For OCI repositories, additional registry-specific authentication is configured (including Docker config)
	opts := &ClientOpts{
		GetterOpts: []helmgetter.Option{
			helmgetter.WithURL(url),
			helmgetter.WithTimeout(obj.GetTimeout()),
			helmgetter.WithPassCredentialsAll(obj.Spec.PassCredentials),
		},
		Insecure: obj.Spec.Insecure,
	}

	// Process secrets and configure authentication
	deprecatedTLS, certSecret, authSecret, err := configureAuthentication(ctx, c, obj, opts, url)
	if err != nil {
		return nil, "", err
	}

	// Setup OCI registry specific configurations if needed
	var tempCertDir string
	if obj.Spec.Type == sourcev1.HelmRepositoryTypeOCI {
		tempCertDir, err = configureOCIRegistryWithSecrets(ctx, obj, opts, url, certSecret, authSecret)
		if err != nil {
			return nil, "", err
		}
	}

	var deprecatedErr error
	if deprecatedTLS {
		deprecatedErr = ErrDeprecatedTLSConfig
	}

	return opts, tempCertDir, deprecatedErr
}

// configureAuthentication processes all secret references and sets up authentication.
// Returns (deprecatedTLS, certSecret, authSecret, error) where:
// - deprecatedTLS: true if TLS config comes from SecretRef (deprecated pattern)
// - certSecret: the secret from CertSecretRef (nil if not specified)
// - authSecret: the secret from SecretRef (nil if not specified)
func configureAuthentication(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, opts *ClientOpts, url string) (bool, *corev1.Secret, *corev1.Secret, error) {
	var deprecatedTLS bool
	var certSecret, authSecret *corev1.Secret

	if obj.Spec.CertSecretRef != nil {
		secret, err := fetchSecret(ctx, c, obj.Spec.CertSecretRef.Name, obj.GetNamespace())
		if err != nil {
			return false, nil, nil, fmt.Errorf("failed to get TLS authentication secret: %w", err)
		}
		certSecret = secret

		tlsConfig, err := secrets.TLSConfigFromSecret(ctx, secret)
		if err != nil {
			return false, nil, nil, fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
		}
		opts.TlsConfig = tlsConfig
	}

	// Extract all authentication methods from SecretRef.
	// This secret may contain multiple auth types (Basic Auth, TLS).
	if obj.Spec.SecretRef != nil {
		secret, err := fetchSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			return false, nil, nil, fmt.Errorf("failed to get authentication secret: %w", err)
		}
		authSecret = secret

		methods, err := secrets.AuthMethodsFromSecret(ctx, secret)
		if err != nil {
			return false, nil, nil, fmt.Errorf("failed to detect authentication methods: %w", err)
		}

		if methods.HasBasicAuth() {
			opts.GetterOpts = append(opts.GetterOpts,
				helmgetter.WithBasicAuth(methods.Basic.Username, methods.Basic.Password))
		}

		// Use TLS from SecretRef only if CertSecretRef is not specified (CertSecretRef takes priority)
		if opts.TlsConfig == nil && methods.HasTLS() {
			opts.TlsConfig = methods.TLS
			deprecatedTLS = true
		}
	}

	return deprecatedTLS, certSecret, authSecret, nil
}

// configureOCIRegistryWithSecrets sets up OCI-specific configurations using pre-fetched secrets
func configureOCIRegistryWithSecrets(ctx context.Context, obj *sourcev1.HelmRepository, opts *ClientOpts, url string, certSecret, authSecret *corev1.Secret) (string, error) {
	// Configure OCI authentication from authSecret if available
	if authSecret != nil {
		keychain, err := registry.LoginOptionFromSecret(url, *authSecret)
		if err != nil {
			return "", fmt.Errorf("failed to configure login options: %w", err)
		}
		opts.Keychain = keychain
	}

	// Handle OCI provider authentication if no SecretRef
	if obj.Spec.SecretRef == nil && obj.Spec.Provider != "" && obj.Spec.Provider != sourcev1.GenericOCIProvider {
		authenticator, err := soci.OIDCAuth(ctx, url, obj.Spec.Provider)
		if err != nil {
			return "", fmt.Errorf("failed to get credential from '%s': %w", obj.Spec.Provider, err)
		}
		opts.Authenticator = authenticator
	}

	// Setup registry login options
	loginOpt, err := registry.NewLoginOption(opts.Authenticator, opts.Keychain, url)
	if err != nil {
		return "", err
	}

	if loginOpt != nil {
		opts.RegLoginOpts = []helmreg.LoginOption{loginOpt, helmreg.LoginOptInsecure(obj.Spec.Insecure)}
	}

	// Handle TLS certificate files for OCI
	var tempCertDir string
	if opts.TlsConfig != nil {
		tempCertDir, err = os.MkdirTemp("", "helm-repo-oci-certs")
		if err != nil {
			return "", fmt.Errorf("cannot create temporary directory: %w", err)
		}

		var tlsSecret *corev1.Secret
		if certSecret != nil {
			tlsSecret = certSecret
		} else if authSecret != nil {
			tlsSecret = authSecret
		}

		certFile, keyFile, caFile, err := storeTLSCertificateFilesForOCI(ctx, tlsSecret, nil, tempCertDir)
		if err != nil {
			return "", fmt.Errorf("cannot write certs files to path: %w", err)
		}

		tlsLoginOpt := registry.TLSLoginOption(certFile, keyFile, caFile)
		if tlsLoginOpt != nil {
			opts.RegLoginOpts = append(opts.RegLoginOpts, tlsLoginOpt)
		}
	}

	return tempCertDir, nil
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
func storeTLSCertificateFilesForOCI(ctx context.Context, certSecret, authSecret *corev1.Secret, path string) (string, string, string, error) {
	var (
		certFile string
		keyFile  string
		caFile   string
		err      error
	)

	// Try to get TLS data from certSecret first, then authSecret
	var tlsSecret *corev1.Secret
	if certSecret != nil {
		tlsSecret = certSecret
	} else if authSecret != nil {
		tlsSecret = authSecret
	}

	if tlsSecret != nil {
		if certData, exists := tlsSecret.Data[secrets.KeyTLSCert]; exists {
			if keyData, keyExists := tlsSecret.Data[secrets.KeyTLSPrivateKey]; keyExists {
				certFile, err = writeToFile(certData, certFileName, path)
				if err != nil {
					return "", "", "", err
				}
				keyFile, err = writeToFile(keyData, keyFileName, path)
				if err != nil {
					return "", "", "", err
				}
			}
		}

		if caData, exists := tlsSecret.Data[secrets.KeyCACert]; exists {
			caFile, err = writeToFile(caData, caFileName, path)
			if err != nil {
				return "", "", "", err
			}
		}
	}

	return certFile, keyFile, caFile, nil
}

func writeToFile(data []byte, filename, tmpDir string) (string, error) {
	file := path.Join(tmpDir, filename)
	err := os.WriteFile(file, data, 0o600)
	if err != nil {
		return "", err
	}
	return file, nil
}
