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

package oci

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/fluxcd/pkg/oci/auth/login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	sourcev1 "github.com/fluxcd/source-controller/api/v1beta2"
)

// Anonymous is an authn.AuthConfig that always returns an anonymous
// authenticator. It is useful for registries that do not require authentication
// or when the credentials are not known.
// It implements authn.Keychain `Resolve` method and can be used as a keychain.
type Anonymous authn.AuthConfig

// Resolve implements authn.Keychain.
func (a Anonymous) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

// OIDCAuth generates the OIDC credential authenticator based on the specified cloud provider.
func OIDCAuth(ctx context.Context, url, provider string, proxyURL *url.URL) (authn.Authenticator, error) {
	u := strings.TrimPrefix(url, sourcev1.OCIRepositoryPrefix)
	ref, err := name.ParseReference(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL '%s': %w", u, err)
	}

	opts := login.ProviderOptions{}
	switch provider {
	case sourcev1.AmazonOCIProvider:
		opts.AwsAutoLogin = true
	case sourcev1.AzureOCIProvider:
		opts.AzureAutoLogin = true
	case sourcev1.GoogleOCIProvider:
		opts.GcpAutoLogin = true
	}

	return login.NewManager(login.WithProxyURL(proxyURL)).Login(ctx, u, ref, opts)
}
