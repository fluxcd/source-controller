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

	"github.com/fluxcd/pkg/oci"
	"github.com/google/go-containerregistry/pkg/authn"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
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
func GetClientOpts(ctx context.Context, c client.Client, obj *helmv1.HelmRepository, url string) (*ClientOpts, string, error) {
	hrOpts := &ClientOpts{
		GetterOpts: []helmgetter.Option{
			helmgetter.WithURL(url),
			helmgetter.WithTimeout(obj.Spec.Timeout.Duration),
			helmgetter.WithPassCredentialsAll(obj.Spec.PassCredentials),
		},
	}
	ociRepo := obj.Spec.Type == helmv1.HelmRepositoryTypeOCI

	var (
		certSecret *corev1.Secret
		tlsBytes   *stls.TLSBytes
		certFile   string
		keyFile    string
		caFile     string
		dir        string
		err        error
	)
	// Check `.spec.certSecretRef` first for any TLS auth data.
	if obj.Spec.CertSecretRef != nil {
		certSecret, err = fetchSecret(ctx, c, obj.Spec.CertSecretRef.Name, obj.GetNamespace())
		if err != nil {
			return nil, "", fmt.Errorf("failed to get TLS authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.CertSecretRef.Name, err)
		}

		hrOpts.TlsConfig, tlsBytes, err = stls.KubeTLSClientConfigFromSecret(*certSecret, url)
		if err != nil {
			return nil, "", fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
		}
	}

	var authSecret *corev1.Secret
	var deprecatedTLSConfig bool
	if obj.Spec.SecretRef != nil {
		authSecret, err = fetchSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			return nil, "", fmt.Errorf("failed to get authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.SecretRef.Name, err)
		}

		// Construct actual Helm client options.
		opts, err := GetterOptionsFromSecret(*authSecret)
		if err != nil {
			return nil, "", fmt.Errorf("failed to configure Helm client: %w", err)
		}
		hrOpts.GetterOpts = append(hrOpts.GetterOpts, opts...)

		// If the TLS config is nil, i.e. one couldn't be constructed using
		// `.spec.certSecretRef`, then try to use `.spec.secretRef`.
		if hrOpts.TlsConfig == nil && !ociRepo {
			hrOpts.TlsConfig, tlsBytes, err = stls.LegacyTLSClientConfigFromSecret(*authSecret, url)
			if err != nil {
				return nil, "", fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
			}
			// Constructing a TLS config using the auth secret is deprecated behavior.
			if hrOpts.TlsConfig != nil {
				deprecatedTLSConfig = true
			}
		}

		if ociRepo {
			hrOpts.Keychain, err = registry.LoginOptionFromSecret(url, *authSecret)
			if err != nil {
				return nil, "", fmt.Errorf("failed to configure login options: %w", err)
			}
		}
	} else if obj.Spec.Provider != helmv1.GenericOCIProvider && obj.Spec.Type == helmv1.HelmRepositoryTypeOCI && ociRepo {
		authenticator, authErr := soci.OIDCAuth(ctx, obj.Spec.URL, obj.Spec.Provider)
		if authErr != nil && !errors.Is(authErr, oci.ErrUnconfiguredProvider) {
			return nil, "", fmt.Errorf("failed to get credential from '%s': %w", obj.Spec.Provider, authErr)
		}
		if authenticator != nil {
			hrOpts.Authenticator = authenticator
		}
	}

	if ociRepo {
		// Persist the certs files to the path if needed.
		if tlsBytes != nil {
			dir, err = os.MkdirTemp("", "helm-repo-oci-certs")
			if err != nil {
				return nil, "", fmt.Errorf("cannot create temporary directory: %w", err)
			}
			certFile, keyFile, caFile, err = storeTLSCertificateFiles(tlsBytes, dir)
			if err != nil {
				return nil, "", fmt.Errorf("cannot write certs files to path: %w", err)
			}
		}
		loginOpt, err := registry.NewLoginOption(hrOpts.Authenticator, hrOpts.Keychain, url)
		if err != nil {
			return nil, "", err
		}
		if loginOpt != nil {
			hrOpts.RegLoginOpts = []helmreg.LoginOption{loginOpt}
		}
		tlsLoginOpt := registry.TLSLoginOption(certFile, keyFile, caFile)
		if tlsLoginOpt != nil {
			hrOpts.RegLoginOpts = append(hrOpts.RegLoginOpts, tlsLoginOpt)
		}
	}
	if deprecatedTLSConfig {
		err = ErrDeprecatedTLSConfig
	}

	return hrOpts, dir, err
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
	err := os.WriteFile(file, data, 0o644)
	if err != nil {
		return "", err
	}
	return file, nil
}
