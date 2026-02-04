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

package registry

import (
	"bytes"
	"fmt"
	"net/url"

	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/credentials"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/werf/nelm-source-controller/internal/helm/common"
	"github.com/werf/nelm-source-controller/internal/oci"
	"helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
)

// helper is a subset of the Docker credential helper credentials.Helper interface used by NewKeychainFromHelper.
type helper struct {
	registry           string
	username, password string
	err                error
}

func (h helper) Get(serverURL string) (string, string, error) {
	if serverURL != h.registry {
		return "", "", fmt.Errorf("unexpected serverURL: %s", serverURL)
	}
	return h.username, h.password, h.err
}

// LoginOptionFromSecret derives authentication data from a Secret to login to an OCI registry. This Secret
// may either hold "username" and "password" fields or be of the corev1.SecretTypeDockerConfigJson type and hold
// a corev1.DockerConfigJsonKey field with a complete Docker configuration. If both, "username" and "password" are
// empty, a nil LoginOption and a nil error will be returned.
func LoginOptionFromSecret(registryURL string, secret corev1.Secret) (authn.Keychain, error) {
	var username, password string
	parsedURL, err := url.Parse(registryURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse registry URL '%s' while reconciling Secret '%s': %w",
			registryURL, secret.Name, err)
	}
	if secret.Type == corev1.SecretTypeDockerConfigJson {
		dockerCfg, err := config.LoadFromReader(bytes.NewReader(secret.Data[corev1.DockerConfigJsonKey]))
		if err != nil {
			return nil, fmt.Errorf("unable to load Docker config from Secret '%s': %w", secret.Name, err)
		}
		authConfig, err := dockerCfg.GetAuthConfig(parsedURL.Host)
		if err != nil {
			return nil, fmt.Errorf("unable to get authentication data from Secret '%s': %w", secret.Name, err)
		}

		// Make sure that the obtained auth config is for the requested host.
		// When the docker config does not contain the credentials for a host,
		// the credential store returns an empty auth config.
		// Refer: https://github.com/docker/cli/blob/v20.10.16/cli/config/credentials/file_store.go#L44
		if credentials.ConvertToHostname(authConfig.ServerAddress) != parsedURL.Host {
			return nil, fmt.Errorf("no auth config for '%s' in the docker-registry Secret '%s'", parsedURL.Host, secret.Name)
		}
		username = authConfig.Username
		password = authConfig.Password
	} else {
		username, password = string(secret.Data["username"]), string(secret.Data["password"])
	}
	switch {
	case username == "" && password == "":
		return oci.Anonymous{}, nil
	case username == "" || password == "":
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'username' and 'password'", secret.Name)
	}
	return authn.NewKeychainFromHelper(helper{registry: parsedURL.Host, username: username, password: password}), nil
}

// KeyChainAdaptHelper returns an ORAS credentials callback configured with the authorization data
// from the given authn keychain. This allows for example to make use of credential helpers from
// cloud providers.
// Ref: https://github.com/google/go-containerregistry/tree/main/pkg/authn
func KeychainAdaptHelper(keyChain authn.Keychain) func(string) (registry.LoginOption, error) {
	return func(registryURL string) (registry.LoginOption, error) {
		parsedURL, err := url.Parse(registryURL)
		if err != nil {
			return nil, fmt.Errorf("unable to parse registry URL '%s'", registryURL)
		}
		authenticator, err := keyChain.Resolve(common.StringResource{Registry: parsedURL.Host})
		if err != nil {
			return nil, fmt.Errorf("unable to resolve credentials for registry '%s': %w", registryURL, err)
		}

		return AuthAdaptHelper(authenticator)
	}
}

// AuthAdaptHelper returns an ORAS credentials callback configured with the authorization data
// from the given authn authenticator. This allows for example to make use of credential helpers from
// cloud providers.
// Ref: https://github.com/google/go-containerregistry/tree/main/pkg/authn
func AuthAdaptHelper(auth authn.Authenticator) (registry.LoginOption, error) {
	authConfig, err := auth.Authorization()
	if err != nil {
		return nil, fmt.Errorf("unable to get authentication data from OIDC: %w", err)
	}

	username := authConfig.Username
	password := authConfig.Password

	switch {
	case username == "" && password == "":
		return nil, nil
	case username == "" || password == "":
		return nil, fmt.Errorf("invalid auth data: required fields 'username' and 'password'")
	}
	return registry.LoginOptBasicAuth(username, password), nil
}

// NewLoginOption returns a registry login option for the given HelmRepository.
// If the HelmRepository does not specify a secretRef, a nil login option is returned.
func NewLoginOption(auth authn.Authenticator, keychain authn.Keychain, registryURL string) (registry.LoginOption, error) {
	if auth != nil {
		return AuthAdaptHelper(auth)
	}

	if keychain != nil {
		return KeychainAdaptHelper(keychain)(registryURL)
	}

	return nil, nil
}

// TLSLoginOption returns a LoginOption that can be used to configure the TLS client.
// It requires either the caFile or both certFile and keyFile to be not blank.
func TLSLoginOption(certFile, keyFile, caFile string) registry.LoginOption {
	if (certFile != "" && keyFile != "") || caFile != "" {
		return registry.LoginOptTLSClientConfig(certFile, keyFile, caFile)
	}

	return nil
}
