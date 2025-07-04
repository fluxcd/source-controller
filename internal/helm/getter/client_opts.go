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

	"github.com/fluxcd/pkg/runtime/secrets"
	"github.com/google/go-containerregistry/pkg/authn"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sourcev1 "github.com/fluxcd/source-controller/api/v1"
	"github.com/fluxcd/source-controller/internal/helm/registry"
	soci "github.com/fluxcd/source-controller/internal/oci"
	stls "github.com/fluxcd/source-controller/internal/tls"
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
	hrOpts := &ClientOpts{
		GetterOpts: []helmgetter.Option{
			helmgetter.WithURL(url),
			helmgetter.WithTimeout(obj.GetTimeout()),
			helmgetter.WithPassCredentialsAll(obj.Spec.PassCredentials),
		},
	}
	ociRepo := obj.Spec.Type == sourcev1.HelmRepositoryTypeOCI

	// Setup TLS from dedicated cert secret
	tlsBytes, err := setupCertSecret(ctx, c, obj, url, hrOpts)
	if err != nil {
		return nil, "", err
	}

	// Setup authentication and optional legacy TLS
	deprecatedTLSConfig, err := setupAuthSecret(ctx, c, obj, url, hrOpts, &tlsBytes, ociRepo)
	if err != nil {
		return nil, "", err
	}

	// Setup OCI provider authentication
	err = setupOCIAuth(ctx, obj, hrOpts, ociRepo)
	if err != nil {
		return nil, "", err
	}

	// Setup OCI registry configuration
	dir, err := setupOCIRegistry(hrOpts, tlsBytes, url, obj, ociRepo)
	if err != nil {
		return nil, "", err
	}

	if deprecatedTLSConfig {
		err = ErrDeprecatedTLSConfig
	}

	hrOpts.Insecure = obj.Spec.Insecure
	return hrOpts, dir, err
}

// TODO: Remove fetchSecret once runtime/secrets migration is complete.
// This helper function will be replaced by runtime/secrets package functionality.
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

// storeTLSCertificateFiles writes the certs files to the given path and returns the files paths.
func storeTLSCertificateFiles(tlsBytes *stls.TLSBytes, path string) (string, string, string, error) {
	var (
		certFile string
		keyFile  string
		caFile   string
		err      error
	)
	if len(tlsBytes.CertBytes) > 0 && len(tlsBytes.KeyBytes) > 0 {
		certFile, err = writeToFile(tlsBytes.CertBytes, certFileName, path)
		if err != nil {
			return "", "", "", err
		}
		keyFile, err = writeToFile(tlsBytes.KeyBytes, keyFileName, path)
		if err != nil {
			return "", "", "", err
		}
	}
	if len(tlsBytes.CABytes) > 0 {
		caFile, err = writeToFile(tlsBytes.CABytes, caFileName, path)
		if err != nil {
			return "", "", "", err
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

// setupCertSecret configures TLS from the dedicated cert secret (.spec.certSecretRef)
func setupCertSecret(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, url string, hrOpts *ClientOpts) (*stls.TLSBytes, error) {
	if obj.Spec.CertSecretRef == nil {
		return nil, nil
	}

	// TODO: Replace with runtime/secrets package functionality once migration is complete
	certSecret, err := fetchSecret(ctx, c, obj.Spec.CertSecretRef.Name, obj.GetNamespace())
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.CertSecretRef.Name, err)
	}

	// TODO: Replace with runtime/secrets.TLSConfigFromSecret once migration is complete
	tlsConfig, tlsBytes, err := stls.KubeTLSClientConfigFromSecret(*certSecret, url)
	if err != nil {
		return nil, fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
	}

	hrOpts.TlsConfig = tlsConfig
	return tlsBytes, nil
}

// setupAuthSecret configures authentication from .spec.secretRef (Basic Auth, Docker config, or legacy TLS)
func setupAuthSecret(ctx context.Context, c client.Client, obj *sourcev1.HelmRepository, url string, hrOpts *ClientOpts, tlsBytes **stls.TLSBytes, ociRepo bool) (bool, error) {
	if obj.Spec.SecretRef == nil {
		return false, nil
	}

	// TODO: Replace with runtime/secrets package functionality once migration is complete
	authSecret, err := fetchSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
	if err != nil {
		return false, fmt.Errorf("failed to get authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.SecretRef.Name, err)
	}

	// Try Basic Auth first (highest priority), then fall back to Docker config or legacy TLS
	username, password, err := secrets.BasicAuthFromSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
	if err != nil {
		// Basic Auth failed - check if it's a Docker config secret or legacy TLS-only secret
		_, hasDockerConfig := authSecret.Data[".dockerconfigjson"]
		_, hasCAFile := authSecret.Data["caFile"]
		_, hasCertFile := authSecret.Data["certFile"]
		_, hasKeyFile := authSecret.Data["keyFile"]
		hasLegacyTLS := hasCAFile || hasCertFile || hasKeyFile
		if !hasDockerConfig && !hasLegacyTLS {
			// Not a Docker config or legacy TLS-only secret, so Basic Auth failure is an error
			return false, err
		}
		// Docker config or legacy TLS-only secret - Basic Auth failure is expected, continue
	} else {
		hrOpts.GetterOpts = append(hrOpts.GetterOpts, helmgetter.WithBasicAuth(username, password))
	}

	// Setup legacy TLS if no dedicated cert secret was configured
	deprecatedTLSConfig := false
	if hrOpts.TlsConfig == nil && !ociRepo {
		// TODO: Replace with runtime/secrets.TLSConfigFromSecret once migration is complete
		tlsConfig, legacyTLSBytes, err := stls.LegacyTLSClientConfigFromSecret(*authSecret, url)
		if err != nil {
			return false, fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
		}
		hrOpts.TlsConfig = tlsConfig
		if tlsConfig != nil {
			deprecatedTLSConfig = true
			*tlsBytes = legacyTLSBytes
		}
	}

	// Setup OCI authentication if this is an OCI repository
	if ociRepo {
		keychain, err := registry.LoginOptionFromSecretRef(ctx, c, url, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			return false, fmt.Errorf("failed to configure login options: %w", err)
		}
		hrOpts.Keychain = keychain
	}

	return deprecatedTLSConfig, nil
}

// setupOCIAuth configures OCI provider authentication when no secret is configured
func setupOCIAuth(ctx context.Context, obj *sourcev1.HelmRepository, hrOpts *ClientOpts, ociRepo bool) error {
	// Only setup provider auth if no secret is configured and it's an OCI repo with a non-generic provider
	if obj.Spec.SecretRef != nil || !ociRepo {
		return nil
	}

	provider := obj.Spec.Provider
	if provider == "" || provider == sourcev1.GenericOCIProvider {
		return nil
	}

	authenticator, err := soci.OIDCAuth(ctx, obj.Spec.URL, provider)
	if err != nil {
		return fmt.Errorf("failed to get credential from '%s': %w", provider, err)
	}

	hrOpts.Authenticator = authenticator
	return nil
}

// setupOCIRegistry configures OCI registry login options and certificate files
func setupOCIRegistry(hrOpts *ClientOpts, tlsBytes *stls.TLSBytes, url string, obj *sourcev1.HelmRepository, ociRepo bool) (string, error) {

	var dir string
	var certFile, keyFile, caFile string
	var err error

	// Persist the certs files to the path if needed
	if tlsBytes != nil {
		dir, err = os.MkdirTemp("", "helm-repo-oci-certs")
		if err != nil {
			return "", fmt.Errorf("cannot create temporary directory: %w", err)
		}
		certFile, keyFile, caFile, err = storeTLSCertificateFiles(tlsBytes, dir)
		if err != nil {
			return "", fmt.Errorf("cannot write certs files to path: %w", err)
		}
	}

	loginOpt, err := registry.NewLoginOption(hrOpts.Authenticator, hrOpts.Keychain, url)
	if err != nil {
		return "", err
	}

	if loginOpt != nil {
		hrOpts.RegLoginOpts = []helmreg.LoginOption{loginOpt, helmreg.LoginOptInsecure(obj.Spec.Insecure)}
		tlsLoginOpt := registry.TLSLoginOption(certFile, keyFile, caFile)
		if tlsLoginOpt != nil {
			hrOpts.RegLoginOpts = append(hrOpts.RegLoginOpts, tlsLoginOpt)
		}
	}

	return dir, nil
}
