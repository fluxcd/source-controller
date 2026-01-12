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

	"github.com/google/go-containerregistry/pkg/authn"
	helmgetter "helm.sh/helm/v4/pkg/getter"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"oras.land/oras-go/v2/registry/remote/auth"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/runtime/secrets"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/fluxcd/source-controller/internal/helm/registry"
	soci "github.com/fluxcd/source-controller/internal/oci"
)

var ErrDeprecatedTLSConfig = errors.New("TLS configured in a deprecated manner")

// ClientOpts contains the various options to use while constructing
// a Helm repository client.
type ClientOpts struct {
	Authenticator authn.Authenticator
	Keychain      authn.Keychain
	TLSConfig     *tls.Config
	GetterOpts    []helmgetter.Option
	Insecure      bool
	OCIAuth       auth.CredentialFunc
}

// GetClientOpts uses the provided HelmRepository object and a normalized
// URL to construct a HelmClientOpts object. If obj is an OCI HelmRepository,
// then the returned options object will also contain the required registry
// auth mechanisms.
func GetClientOpts(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, url string) (*ClientOpts, error) {
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
	deprecatedTLS, authSecret, err := configureAuthentication(ctx, c, obj, opts)
	if err != nil {
		return nil, err
	}

	// Setup OCI registry specific configurations if needed
	if obj.Spec.Type == sourcev1.HelmRepositoryTypeOCI {
		if err := configureOCIRegistryWithSecrets(ctx, obj, opts, url, authSecret); err != nil {
			return nil, err
		}
	}

	var deprecatedErr error
	if deprecatedTLS {
		deprecatedErr = ErrDeprecatedTLSConfig
	}

	return opts, deprecatedErr
}

// configureAuthentication processes all secret references and sets up authentication.
// Returns (deprecatedTLS, authSecret, error) where:
// - deprecatedTLS: true if TLS config comes from SecretRef (deprecated pattern)
// - authSecret: the secret from SecretRef (nil if not specified)
func configureAuthentication(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, opts *ClientOpts) (bool, *corev1.Secret, error) {
	var deprecatedTLS bool
	var authSecret *corev1.Secret

	if obj.Spec.CertSecretRef != nil {
		secret, err := fetchSecret(ctx, c, obj.Spec.CertSecretRef.Name, obj.GetNamespace())
		if err != nil {
			secretRef := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.Spec.CertSecretRef.Name}
			return false, nil, fmt.Errorf("failed to get TLS authentication secret '%s': %w", secretRef, err)
		}

		// NOTE: Use WithSystemCertPool to maintain backward compatibility with the existing
		// extend approach (system CAs + user CA) rather than the default replace approach (user CA only).
		// This ensures HelmRepository continues to work with both system and user-provided CA certificates.
		var tlsOpts = []secrets.TLSConfigOption{secrets.WithSystemCertPool()}
		tlsConfig, err := secrets.TLSConfigFromSecret(ctx, secret, tlsOpts...)
		if err != nil {
			return false, nil, fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
		}
		opts.TLSConfig = tlsConfig
	}

	// Extract all authentication methods from SecretRef.
	// This secret may contain multiple auth types (Basic Auth, TLS).
	if obj.Spec.SecretRef != nil {
		secret, err := fetchSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			secretRef := types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.Spec.SecretRef.Name}
			return false, nil, fmt.Errorf("failed to get authentication secret '%s': %w", secretRef, err)
		}
		authSecret = secret

		// NOTE: Use WithTLSSystemCertPool to maintain backward compatibility with the existing
		// extend approach (system CAs + user CA) rather than the default replace approach (user CA only).
		// This ensures HelmRepository auth methods work with both system and user-provided CA certificates.
		var authOpts = []secrets.AuthMethodsOption{
			secrets.WithTLSSystemCertPool(),
		}
		methods, err := secrets.AuthMethodsFromSecret(ctx, secret, authOpts...)
		if err != nil {
			return false, nil, fmt.Errorf("failed to detect authentication methods: %w", err)
		}

		if methods.HasBasicAuth() {
			opts.GetterOpts = append(opts.GetterOpts,
				helmgetter.WithBasicAuth(methods.Basic.Username, methods.Basic.Password))
		}

		// Use TLS from SecretRef only if CertSecretRef is not specified (CertSecretRef takes priority)
		if opts.TLSConfig == nil && methods.HasTLS() {
			opts.TLSConfig = methods.TLS
			deprecatedTLS = true
		}
	}

	return deprecatedTLS, authSecret, nil
}

// configureOCIRegistryWithSecrets sets up OCI-specific configurations using pre-fetched secrets
func configureOCIRegistryWithSecrets(ctx context.Context, obj *sourcev1.HelmRepository, opts *ClientOpts, url string, authSecret *corev1.Secret) error {
	// Configure OCI authentication from authSecret if available
	if authSecret != nil {
		keychain, err := registry.KeychainFromSecret(url, *authSecret)
		if err != nil {
			return fmt.Errorf("failed to configure OCI registry authentication: %w", err)
		}
		opts.Keychain = keychain
	}

	// Handle OCI provider authentication if no SecretRef
	if obj.Spec.SecretRef == nil && obj.Spec.Provider != "" && obj.Spec.Provider != sourcev1.GenericOCIProvider {
		authenticator, err := soci.OIDCAuth(ctx, url, obj.Spec.Provider)
		if err != nil {
			return fmt.Errorf("failed to get credential from '%s': %w", obj.Spec.Provider, err)
		}
		opts.Authenticator = authenticator
	}

	// Build registry authentication
	creds, err := registry.NewCredentials(opts.Authenticator, opts.Keychain, url)
	if err != nil {
		return err
	}
	opts.OCIAuth = creds

	return nil
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
