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
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/k8schain"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmreg "helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/fluxcd/pkg/oci"
	helmv1 "github.com/fluxcd/source-controller/api/v1beta2"
	"github.com/fluxcd/source-controller/internal/helm/registry"
	soci "github.com/fluxcd/source-controller/internal/oci"
)

var ErrDeprecatedTLSConfig = errors.New("TLS configured in a deprecated manner")

// ClientOpts contains the various options to use while constructing
// a Helm repository client.
type ClientOpts struct {
	Authenticator authn.Authenticator
	Keychain      authn.Keychain
	RegLoginOpt   helmreg.LoginOption
	TlsConfig     *tls.Config
	GetterOpts    []helmgetter.Option
}

// GetClientOpts uses the provided HelmRepository object and a normalized
// URL to construct a HelmClientOpts object. If obj is an OCI HelmRepository,
// then the returned options object will also contain the required registry
// auth mechanisms.
func GetClientOpts(ctx context.Context, c client.Client, obj *helmv1.HelmRepository, url string) (*ClientOpts, error) {
	hrOpts := &ClientOpts{
		GetterOpts: []helmgetter.Option{
			helmgetter.WithURL(url),
			helmgetter.WithTimeout(obj.Spec.Timeout.Duration),
			helmgetter.WithPassCredentialsAll(obj.Spec.PassCredentials),
		},
	}
	ociRepo := obj.Spec.Type == helmv1.HelmRepositoryTypeOCI

	var certSecret *corev1.Secret
	var err error
	// Check `.spec.certSecretRef` first for any TLS auth data.
	if obj.Spec.CertSecretRef != nil {
		certSecret, err = fetchSecret(ctx, c, obj.Spec.CertSecretRef.Name, obj.GetNamespace())
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.CertSecretRef.Name, err)
		}

		hrOpts.TlsConfig, err = TLSClientConfigFromSecret(*certSecret, url)
		if err != nil {
			return nil, fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
		}
	}

	var authSecret *corev1.Secret
	var deprecatedTLSConfig bool

	if obj.Spec.SecretRef != nil {
		authSecret, err = fetchSecret(ctx, c, obj.Spec.SecretRef.Name, obj.GetNamespace())
		if err != nil {
			return nil, fmt.Errorf("failed to get authentication secret '%s/%s': %w", obj.GetNamespace(), obj.Spec.SecretRef.Name, err)
		}

		// Construct actual Helm client options.
		opts, err := GetterOptionsFromSecret(*authSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to configure Helm client: %w", err)
		}
		hrOpts.GetterOpts = append(hrOpts.GetterOpts, opts...)

		// If the TLS config is nil, i.e. one couldn't be constructed using `.spec.certSecretRef`
		// then try to use `.spec.certSecretRef`.
		if hrOpts.TlsConfig == nil {
			hrOpts.TlsConfig, err = TLSClientConfigFromSecret(*authSecret, url)
			if err != nil {
				return nil, fmt.Errorf("failed to construct Helm client's TLS config: %w", err)
			}
			// Constructing a TLS config using the auth secret is deprecated behavior.
			if hrOpts.TlsConfig != nil {
				deprecatedTLSConfig = true
			}
		}

		if ociRepo {
			hrOpts.Keychain, err = registry.LoginOptionFromSecret(url, *authSecret)
			if err != nil {
				return nil, fmt.Errorf("failed to configure login options: %w", err)
			}
		}
	}

	if ociRepo {
		if obj.Spec.ServiceAccountName != "" {
			keychain, err := getKeychainFromSAImagePullSecrets(ctx, c, obj.GetNamespace(), obj.Spec.ServiceAccountName)
			if err != nil {
				return nil, fmt.Errorf("failed to get keychain from service account: %w", err)
			}

			if hrOpts.Keychain != nil {
				hrOpts.Keychain = authn.NewMultiKeychain(hrOpts.Keychain, keychain)
			} else {
				hrOpts.Keychain = keychain
			}
		}

		var hasKeychain bool
		if hrOpts.Keychain != nil {
			_, ok := hrOpts.Keychain.(soci.Anonymous)
			hasKeychain = !ok
		}

		if !hasKeychain && obj.Spec.Provider != helmv1.GenericOCIProvider {
			authenticator, authErr := soci.OIDCAuth(ctx, obj.Spec.URL, obj.Spec.Provider)
			if authErr != nil && !errors.Is(authErr, oci.ErrUnconfiguredProvider) {
				return nil, fmt.Errorf("failed to get credential from '%s': %w", obj.Spec.Provider, authErr)
			}
			if authenticator != nil {
				hrOpts.Authenticator = authenticator
			}
		}

		hrOpts.RegLoginOpt, err = registry.NewLoginOption(hrOpts.Authenticator, hrOpts.Keychain, url)
		if err != nil {
			return nil, err
		}
	}
	if deprecatedTLSConfig {
		err = ErrDeprecatedTLSConfig
	}

	return hrOpts, err
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

// TLSClientConfigFromSecret attempts to construct a TLS client config
// for the given v1.Secret. It returns the TLS client config or an error.
//
// Secrets with no certFile, keyFile, AND caFile are ignored, if only a
// certBytes OR keyBytes is defined it returns an error.
func TLSClientConfigFromSecret(secret corev1.Secret, repositoryUrl string) (*tls.Config, error) {
	certBytes, keyBytes, caBytes := secret.Data["certFile"], secret.Data["keyFile"], secret.Data["caFile"]
	switch {
	case len(certBytes)+len(keyBytes)+len(caBytes) == 0:
		return nil, nil
	case (len(certBytes) > 0 && len(keyBytes) == 0) || (len(keyBytes) > 0 && len(certBytes) == 0):
		return nil, fmt.Errorf("invalid '%s' secret data: fields 'certFile' and 'keyFile' require each other's presence",
			secret.Name)
	}

	tlsConf := &tls.Config{}
	if len(certBytes) > 0 && len(keyBytes) > 0 {
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return nil, err
		}
		tlsConf.Certificates = append(tlsConf.Certificates, cert)
	}

	if len(caBytes) > 0 {
		cp, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve system certificate pool: %w", err)
		}
		if !cp.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("cannot append certificate into certificate pool: invalid caFile")
		}

		tlsConf.RootCAs = cp
	}

	tlsConf.BuildNameToCertificate()

	u, err := url.Parse(repositoryUrl)
	if err != nil {
		return nil, fmt.Errorf("cannot parse repository URL: %w", err)
	}

	tlsConf.ServerName = u.Hostname()

	return tlsConf, nil
}

// getKeychainFromSAImagePullSecrets returns an authn.Keychain gotten from the image pull secrets attached to a
// service account.
func getKeychainFromSAImagePullSecrets(ctx context.Context, c client.Client, ns, saName string) (authn.Keychain, error) {
	serviceAccount := corev1.ServiceAccount{}
	// Lookup service account
	if err := c.Get(ctx, types.NamespacedName{
		Namespace: ns,
		Name:      saName,
	}, &serviceAccount); err != nil {
		return nil, fmt.Errorf("failed to get serviceaccout: %s", err)
	}

	if len(serviceAccount.ImagePullSecrets) > 0 {
		imagePullSecrets := make([]corev1.Secret, len(serviceAccount.ImagePullSecrets))
		for i, ips := range serviceAccount.ImagePullSecrets {
			var saAuthSecret corev1.Secret
			if err := c.Get(ctx, types.NamespacedName{
				Namespace: ns,
				Name:      ips.Name,
			}, &saAuthSecret); err != nil {
				return nil, fmt.Errorf("failed to get image pull secret '%s' for serviceaccount '%s': %w",
					ips.Name, saName, err)
			}
			imagePullSecrets[i] = saAuthSecret
		}

		return k8schain.NewFromPullSecrets(ctx, imagePullSecrets)
	}

	return nil, nil
}
