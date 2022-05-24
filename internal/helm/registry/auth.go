package registry

import (
	"bytes"
	"fmt"
	"net/url"

	"github.com/docker/cli/cli/config"
	"helm.sh/helm/v3/pkg/registry"
	corev1 "k8s.io/api/core/v1"
)

// LoginOptionFromSecret derives authentication data from a Secret to login to an OCI registry. This Secret
// may either hold "username" and "password" fields or be of the corev1.SecretTypeDockerConfigJson type and hold
// a corev1.DockerConfigJsonKey field with a complete Docker configuration. If both, "username" and "password" are
// empty, a nil LoginOption and a nil error will be returned.
func LoginOptionFromSecret(registryURL string, secret corev1.Secret) (registry.LoginOption, error) {
	var username, password string
	if secret.Type == corev1.SecretTypeDockerConfigJson {
		dockerCfg, err := config.LoadFromReader(bytes.NewReader(secret.Data[corev1.DockerConfigJsonKey]))
		if err != nil {
			return nil, fmt.Errorf("unable to load Docker config from Secret '%s': %w", secret.Name, err)
		}
		parsedURL, err := url.Parse(registryURL)
		if err != nil {
			return nil, fmt.Errorf("unable to parse registry URL '%s' while reconciling Secret '%s': %w",
				registryURL, secret.Name, err)
		}
		authConfig, err := dockerCfg.GetAuthConfig(parsedURL.Host)
		if err != nil {
			return nil, fmt.Errorf("unable to get authentication data from Secret '%s': %w", secret.Name, err)
		}
		username = authConfig.Username
		password = authConfig.Password
	} else {
		username, password = string(secret.Data["username"]), string(secret.Data["password"])
	}
	switch {
	case username == "" && password == "":
		return nil, nil
	case username == "" || password == "":
		return nil, fmt.Errorf("invalid '%s' secret data: required fields 'username' and 'password'", secret.Name)
	}
	return registry.LoginOptBasicAuth(username, password), nil
}
